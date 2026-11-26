#!/usr/bin/env python3
"""Prepare and verify pinned Android runtimes without running package install scripts.

The committed signed APT snapshot authenticates every package hash. Default
prepare refuses changes to the reviewed output hashes. --record-output-hashes
is an explicit maintainer operation whose lockfile diff must be reviewed.
"""
import argparse
import concurrent.futures
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "android/native-runtime.lock.json"
PROVENANCE = Path(__file__).resolve().parent / "provenance"
JNI = ROOT / "android/app/src/main/jniLibs"
ASSETS = ROOT / "android/app/src/main/assets/native-runtime"
ABIS = {"aarch64": ("arm64-v8a", 183), "x86_64": ("x86_64", 62)}
# Reviewed on 2026-11-26 from the official sources recorded in
# docs/native-runtime-support-2026-11-26.md. This is a conservative necessary
# production condition, not a runtime compatibility or vulnerability attestation.
SUPPORT_REVIEWED_ON = date(2026, 11, 26)
SUPPORT_REVIEW_UNTIL = date(2026, 12, 26)
MAX_PRODUCTION_SNAPSHOT_DAYS = 30
NODE_24_EOL = date(2028, 4, 30)
OPENSSL_35_EOL = date(2030, 4, 8)
# The 2026-11-24 advisory schedules these releases for 2026-12-01.
# A future version label must not turn an announced fix into an available build.
OPENSSL_35_FIX_AVAILABLE_FROM = date(2026, 12, 1)
OPENSSL_35_PATCH_FLOOR = (3, 5, 10)
SYSTEM_LIBS = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so"}
NAMES = {
    "libz.so.1": "libtx_z.so", "libcares.so": "libtx_cares.so",
    "libsqlite3.so": "libtx_sqlite3.so", "libsqlite3.so.0": "libtx_sqlite3.so",
    "libcrypto.so.3": "libtx_crypto.so", "libssl.so.3": "libtx_ssl.so",
    "libicui18n.so.79": "libtx_icui18n.so", "libicuuc.so.79": "libtx_icuuc.so",
    "libicudata.so.79": "libtx_icudata.so", "libc++_shared.so": "libtx_cxx.so",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


def fail(message):
    raise RuntimeError(message)


def fetch(url, path, expected):
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if digest(data) != expected:
            fail("Download SHA-256 mismatch: " + path.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if digest(path.read_bytes()) != expected:
        fail("Cached SHA-256 mismatch: " + path.name)
    return path


def verify_provenance(lock, work):
    for name, expected in lock["provenance_files"].items():
        if Path(name).name != name or digest((PROVENANCE / name).read_bytes()) != expected:
            fail("Provenance snapshot changed: " + name)
    key = PROVENANCE / "termux-autobuilds.gpg"
    with tempfile.TemporaryDirectory(prefix="gpg-", dir=work) as directory:
        status = run("gpg", "--batch", "--homedir", directory, "--no-default-keyring",
                     "--keyring", str(key), "--status-fd", "1", "--verify", str(PROVENANCE / "termux-InRelease"))
    if "[GNUPG:] VALIDSIG " + lock["termux_signer_fingerprint"] + " " not in status:
        fail("APT snapshot signer does not match the pinned fingerprint")
    release = (PROVENANCE / "termux-InRelease").read_text()
    dates = re.findall(r"^Date: (.+)$", release, re.MULTILINE)
    if len(dates) != 1:
        fail("Signed snapshot Date is missing or ambiguous")
    try:
        signed_time = parsedate_to_datetime(dates[0])
        if signed_time.tzinfo is None:
            raise ValueError("timezone missing")
    except (TypeError, ValueError) as error:
        fail("Signed snapshot Date is invalid: " + str(error))
    if snapshot_time(lock) != signed_time.astimezone(timezone.utc):
        fail("Lock snapshot_date does not match signed metadata")
    block = release.split("SHA256:\n", 1)[1].split("SHA512:\n")[0].split("-----BEGIN PGP SIGNATURE-----")[0]
    hashes = {fields[2]: fields[0] for line in block.splitlines() if len(fields := line.split()) == 3}
    for arch in ABIS:
        data = (PROVENANCE / f"termux-Packages-{arch}.gz").read_bytes()
        if digest(data) != hashes[f"main/binary-{arch}/Packages.gz"]:
            fail("Package index does not match the signed snapshot")
        packages = {}
        for paragraph in gzip.decompress(data).decode().split("\n\n"):
            fields = {}
            for line in paragraph.splitlines():
                if ":" in line and not line.startswith((" ", "\t")):
                    key, value = line.split(":", 1)
                    fields[key] = value.strip()
            if "Package" in fields:
                packages[fields["Package"]] = fields
        for entry in lock["packages"]:
            if entry["indexArch"] != arch:
                continue
            current = packages.get(entry["Package"], {})
            for key in ("Version", "Architecture", "Filename", "SHA256", "Size"):
                if current.get(key) != entry[key]:
                    fail("Package selection does not match signed metadata: " + entry["Package"])
            if entry["Package"] == "nodejs-lts" and entry["Version"] != lock["node_version"]:
                fail("Unexpected Node runtime version")


def elf_machine(data):
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        fail("Expected a version-1 64-bit little-endian ELF file")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or not count or count > 1024 or offset + size * count > len(data):
        fail("Invalid ELF program headers")
    load_segments = 0
    writable = []
    relro = []
    for index in range(count):
        start = offset + index * size
        kind, flags, file_offset, virtual_address, _, file_size, memory_size, alignment = struct.unpack_from("<IIQQQQQQ", data, start)
        if virtual_address + memory_size > 2**64:
            fail("ELF memory segment overflows its address space")
        if kind == 1:
            load_segments += 1
            if alignment < 16384 or alignment & (alignment - 1) or file_offset % 16384 != virtual_address % 16384:
                fail("ELF load segment is not compatible with 16 KiB pages")
            if file_size > memory_size or file_offset + file_size > len(data):
                fail("ELF load segment exceeds its file or memory bounds")
            if flags & 2:
                writable.append((virtual_address, virtual_address + memory_size))
        elif kind == 0x6474e552:  # PT_GNU_RELRO
            relro.append((virtual_address, virtual_address + memory_size))
    if not load_segments:
        fail("ELF has no loadable segments")
    # Android's rounded 16 KiB RELRO protection must not cover later writable
    # bytes. RELRO padding can extend beyond a LOAD: inspect every writable
    # memory range, including BSS, rather than requiring end == LOAD end.
    for _, end in relro:
        rounded_end = (end + 16383) // 16384 * 16384
        if end != rounded_end and any(max(begin, end) < min(finish, rounded_end) for begin, finish in writable):
            fail("ELF writable LOAD overlaps the rounded 16 KiB RELRO protection tail")
    return struct.unpack_from("<H", data, 18)[0]


def elf_linkage_metadata(data):
    """Read only ELF64 file metadata; never execute or dynamically load a file."""
    machine = elf_machine(data)
    if struct.unpack_from("<H", data, 16)[0] != 3:
        fail("Native linkage requires ET_DYN shared libraries or PIE executable")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    loads, executable, dynamics, interpreters, relro = [], [], [], [], []
    for index in range(count):
        segment = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        kind, flags, file_offset, address, _, file_size, memory_size, _ = segment
        if kind == 1:
            loads.append((address, file_offset, file_size))
            if flags & 1:
                executable.append((address, address + file_size))
        elif kind in (2, 3):
            if not file_size or file_offset + file_size > len(data):
                fail("ELF dynamic/interpreter segment exceeds file bounds")
            if kind == 2:
                if file_size > memory_size:
                    fail("ELF dynamic segment exceeds its memory bounds")
                dynamics.append((file_offset, file_size, address))
            else:
                interpreters.append((file_offset, file_size))
        elif kind == 0x6474e552:
            relro.append({"start": address, "end": address + memory_size})
    if len(dynamics) != 1 or len(interpreters) > 1:
        fail("ELF dynamic/interpreter segment is missing or ambiguous")
    begin, length, dynamic_address = dynamics[0]
    if length % 16 or length // 16 > 16384:
        fail("ELF dynamic table has invalid size")
    entries, terminated = [], False
    for index in range(begin, begin + length, 16):
        tag, value = struct.unpack_from("<qQ", data, index)
        if tag == 0:
            terminated = True
            break
        entries.append((tag, value))
    if not terminated:
        fail("ELF dynamic table is not terminated")
    critical = {}
    for tag, value in entries:
        if tag in (5, 10, 14, 15, 29, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff):
            if tag in critical:
                fail("ELF dynamic singleton tag is duplicated")
            critical[tag] = value
    if 5 not in critical or not critical.get(10):
        fail("ELF dynamic string table is missing")
    address, string_size = critical[5], critical[10]
    def file_at(address, length):
        if not length or address + length > 2**64:
            fail("ELF metadata range is invalid")
        mappings = {file_offset + address - start for start, file_offset, file_size in loads
                    if start <= address and address + length <= start + file_size}
        if len(mappings) != 1:
            fail("ELF metadata has no unambiguous file-backed LOAD mapping")
        return mappings.pop()

    if file_at(dynamic_address, length) != begin:
        fail("ELF dynamic segment virtual mapping disagrees with its file offset")
    string_offset = file_at(address, string_size)
    if string_offset + string_size > len(data):
        fail("ELF dynamic string table exceeds file bounds")

    def text(index):
        if index >= string_size:
            fail("ELF dynamic string offset is outside its table")
        begin = string_offset + index
        end = data.find(b"\0", begin, string_offset + string_size)
        if end == -1:
            fail("ELF dynamic string is not terminated")
        if end - begin > 4096:
            fail("ELF dynamic string exceeds the metadata limit")
        try:
            return data[begin:end].decode("ascii")
        except UnicodeDecodeError:
            fail("ELF linkage metadata is not ASCII")

    required = [text(value) for tag, value in entries if tag == 1]
    if len(required) != len(set(required)):
        fail("ELF dependency list contains duplicates")
    interpreter = None
    if interpreters:
        begin, length = interpreters[0]
        raw = data[begin:begin + length]
        if length > 4096 or raw[-1:] != b"\0" or b"\0" in raw[:-1]:
            fail("ELF interpreter string is invalid")
        try:
            interpreter = raw[:-1].decode("ascii")
        except UnicodeDecodeError:
            fail("ELF interpreter string is not ASCII")
    # GNU version metadata is associated with vn_file's exact provider. A
    # definition in some other library, or a VERDEF parent auxiliary name, does
    # not satisfy the provider. This does not resolve dynsym imports or Android
    # platform stubs and is deliberately reported only as a necessary name check.
    version_reads = 0
    def version_record(address, fmt):
        nonlocal version_reads
        version_reads += 1
        if version_reads > 16384:
            fail("ELF version metadata exceeds its bounded record budget")
        return struct.unpack_from(fmt, data, file_at(address, struct.calcsize(fmt)))

    def version_chain(address, count, fmt, next_index):
        if not 1 <= count <= 4096:
            fail("ELF version chain count is invalid")
        seen = set()
        for index in range(count):
            if address in seen:
                fail("ELF version chain repeats a record")
            seen.add(address)
            values = version_record(address, fmt)
            yield address, values
            relative = values[next_index]
            if index + 1 == count:
                if relative:
                    fail("ELF version chain count does not end at its terminator")
            else:
                if relative < struct.calcsize(fmt):
                    fail("ELF version chain is truncated or overlaps records")
                address += relative

    version_needs, version_definitions = {}, []
    need_indices, definition_indices = set(), set()
    for address_tag, count_tag in ((0x6ffffffe, 0x6fffffff), (0x6ffffffc, 0x6ffffffd)):
        if address_tag not in critical and count_tag not in critical:
            continue
        if address_tag not in critical or not critical.get(count_tag):
            fail("ELF version table pointer/count is incomplete")
        address, count = critical[address_tag], critical[count_tag]
        if address_tag == 0x6ffffffe:  # Elf64_Verneed + Elf64_Vernaux
            for current, fields in version_chain(address, count, "<HHIII", 4):
                version, auxiliary_count, provider_offset, auxiliary_offset, _ = fields
                if version != 1 or auxiliary_offset < 16:
                    fail("ELF version-need header is invalid")
                provider = text(provider_offset)
                if not provider or provider in version_needs:
                    fail("ELF version provider is empty or duplicated")
                names = []
                for _, auxiliary in version_chain(current + auxiliary_offset, auxiliary_count, "<IHHII", 4):
                    _, _, raw_index, name_offset, _ = auxiliary
                    index = raw_index & 0x7fff  # GNU hidden bit is not part of the index.
                    if index < 2 or index in need_indices:
                        fail("ELF required version index is invalid or duplicated")
                    need_indices.add(index)
                    name = text(name_offset)
                    if not name or name in names:
                        fail("ELF required version name is empty or duplicated")
                    names.append(name)
                version_needs[provider] = sorted(names)
        else:  # Elf64_Verdef + Elf64_Verdaux
            for current, fields in version_chain(address, count, "<HHHHIII", 6):
                version, _, raw_index, auxiliary_count, _, auxiliary_offset, _ = fields
                index = raw_index & 0x7fff
                if version != 1 or index < 1 or index in definition_indices or auxiliary_offset < 20:
                    fail("ELF version-definition header/index is invalid or duplicated")
                definition_indices.add(index)
                names = [text(auxiliary[0]) for _, auxiliary in version_chain(current + auxiliary_offset, auxiliary_count, "<II", 1)]
                if not names[0] or names[0] in version_definitions:
                    fail("ELF version definition is empty or duplicated")
                version_definitions.append(names[0])  # Remaining auxiliary names are parents.
    entry = struct.unpack_from("<Q", data, 24)[0]
    return {"machine": machine, "needed": required,
            "soname": text(critical[14]) if 14 in critical else None,
            "search_paths": [{"tag": "RPATH" if tag == 15 else "RUNPATH", "value": text(critical[tag])}
                             for tag in (15, 29) if tag in critical],
            "interpreter": interpreter, "entry_point": entry,
            "entry_in_executable_file_segment": bool(entry and any(begin <= entry < end for begin, end in executable)),
            "version_needs": version_needs, "version_definitions": sorted(version_definitions), "relro": relro,
            "relro_16k_tail_check": "passed"}


def verify_linkage(libraries, runtime_names, abi):
    """Verify the actual packaged graph, separately from byte-hash approval."""
    if not {"libnode.so", "libtx_ssl.so", "libtx_crypto.so"}.issubset(runtime_names):
        fail("Native TLS runtime libraries are missing from the runtime inventory")
    graph = {name: elf_linkage_metadata(data) for name, data in libraries.items()}
    node = graph["libnode.so"]
    if not {"libtx_ssl.so", "libtx_crypto.so"}.issubset(node["needed"]):
        fail("Node direct TLS dependencies are missing")
    for name, item in graph.items():
        for library in item["needed"]:
            if not re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", library):
                fail("Unsafe ELF dependency name: " + name)
            if library not in SYSTEM_LIBS and library not in graph:
                fail("Native linkage has an unresolved dependency: " + name + " -> " + library)
        paths = [entry["value"] for entry in item["search_paths"]]
        if name in runtime_names and paths != ["$ORIGIN"]:
            fail("Runtime native search path must be exactly $ORIGIN: " + name)
        if name not in runtime_names and paths not in ([], ["$ORIGIN"]):
            fail("Maven native search path is not local: " + name)
        if name == "libnode.so":
            if not item["entry_in_executable_file_segment"]:
                fail("Node entry must be nonzero in an executable file-backed LOAD")
            if item["interpreter"] != "/system/bin/linker64":
                fail("Node Android interpreter must be /system/bin/linker64")
            if item["soname"] is not None:
                fail("Node executable must not declare a shared SONAME")
        else:
            if item["entry_point"] != 0:
                fail("Shared library must not declare an executable entry: " + name)
            if item["interpreter"] is not None:
                fail("Shared library must not declare an interpreter: " + name)
            if item["soname"] != name:
                fail("Shared SONAME must equal the packaged filename: " + name)
    for name, item in graph.items():
        for provider, versions in item["version_needs"].items():
            if provider not in item["needed"]:
                fail("ELF version provider is not a direct NEEDED library: " + name + " -> " + provider)
            if provider not in SYSTEM_LIBS:
                absent = set(versions) - set(graph[provider]["version_definitions"])
                if absent:
                    fail("ELF provider version definitions are missing: " + name + " -> " + provider + ": " + ", ".join(sorted(absent)))
    if "libtx_crypto.so" not in graph["libtx_ssl.so"]["needed"]:
        fail("TLS crypto edge is missing from libtx_ssl.so")
    reached, pending = set(), ["libnode.so"]
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(library for library in graph[name]["needed"] if library not in SYSTEM_LIBS)
    if not set(runtime_names).issubset(reached):
        fail("Runtime inventory contains libraries unreachable from Node")
    return {"abi": abi, "validation": "static ELF linkage only; no runtime or TLS execution",
            "node_direct_tls": True, "ssl_crypto_edge": True,
            "exact_provider_version_names": "passed",
            "platform_symbol_versions_and_dynsym_resolution": "not_validated_by_this_static_gate",
            "node_reachable_runtime": sorted(set(runtime_names)),
            "libraries": {name: {"sha256": digest(libraries[name]), "provider": "runtime" if name in runtime_names else "maven", **item}
                          for name, item in sorted(graph.items())}}


def needed(path):
    return re.findall(r"\(NEEDED\).*\[([^]]+)\]", run("readelf", "-d", str(path)))


def maven_native_inventory(lock):
    """Return only explicitly reviewed AAR libraries; never wildcard exemptions."""
    artifacts = lock.get("maven_native_artifacts")
    if not isinstance(artifacts, list):
        fail("Maven native artifact manifest is missing")
    inventory = {abi: {} for abi, _ in ABIS.values()}
    for artifact in artifacts:
        coordinate = artifact.get("coordinate", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+", coordinate):
            fail("Unsafe Maven native artifact coordinate")
        group, name, version = coordinate.split(':')
        expected_url = "https://dl.google.com/dl/android/maven2/" + group.replace('.', '/') + '/' + name + '/' + version + '/' + name + '-' + version + '.aar'
        if artifact.get("url") != expected_url or not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")):
            fail("Unexpected Maven native artifact source")
        if set(artifact.get("outputs", {})) != set(inventory):
            fail("Maven native ABI manifest is incomplete")
        for abi, libraries in artifact["outputs"].items():
            if not libraries:
                fail("Maven native library manifest is empty")
            for library, checksum in libraries.items():
                if not re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", library) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                    fail("Unsafe Maven native library manifest")
                if library in inventory[abi] or library in lock["outputs"].get(abi, {}):
                    fail("Maven native library overlaps another reviewed provider")
                inventory[abi][library] = checksum
    return inventory


def verify_maven_native_sources(lock, work):
    """Authenticate AAR inputs and their ELF bytes without adding them to jniLibs.

    Gradle owns merging these libraries from Maven. Copying them here would create
    duplicate native providers and would hide dependency graph changes.
    """
    maven_native_inventory(lock)
    machines = {abi: machine for abi, machine in ABIS.values()}
    for artifact in lock["maven_native_artifacts"]:
        filename = artifact["url"].rsplit('/', 1)[1]
        path = fetch(artifact["url"], work / "maven" / filename, artifact["sha256"])
        with zipfile.ZipFile(path) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                fail("Maven AAR contains duplicate ZIP entries")
            for abi, libraries in artifact["outputs"].items():
                expected_paths = {f"jni/{abi}/{name}" for name in libraries}
                actual_paths = {name for name in archive.namelist() if name.startswith(f"jni/{abi}/") and name.endswith('.so')}
                if actual_paths != expected_paths:
                    fail("Maven AAR native inventory differs from the lock for " + abi)
                for name, checksum in libraries.items():
                    data = archive.read(f"jni/{abi}/{name}")
                    if digest(data) != checksum or elf_machine(data) != machines[abi]:
                        fail("Maven AAR native hash or architecture mismatch: " + abi + '/' + name)
        print("Verified Maven native source " + artifact["coordinate"])


def snapshot_time(lock):
    try:
        timestamp = datetime.fromisoformat(lock["snapshot_date"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timezone missing")
        return timestamp.astimezone(timezone.utc)
    except (KeyError, AttributeError, TypeError, ValueError):
        fail("Native snapshot_date must be a timezone-qualified ISO timestamp")


def package_version(value):
    # Only stable versions and numeric Debian repack revisions are accepted.
    match = re.fullmatch(r"(?:[0-9]+:)?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[0-9]+)?", str(value))
    if not match:
        fail("Native production version is not a stable reviewed format")
    return tuple(int(part) for part in match.groups())


def verify_support_window(lock, today=None):
    """Refuse stale/EOL/unreviewed components even if approval booleans change.

    This function only checks lifecycle, selected package metadata and freshness.
    Source authenticity is separately checked by verify_provenance; output hashes
    and the existing production approval are still independently required.
    """
    now = datetime.now(timezone.utc) if today is None else datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)
    today = now.date()
    versions = {}
    packages = lock.get("packages")
    if not isinstance(packages, list):
        fail("Native component package manifest is missing")
    for name in ("nodejs-lts", "openssl"):
        selected = {}
        selected_strings = set()
        for entry in packages:
            if not isinstance(entry, dict):
                fail("Invalid native component package manifest")
            if entry.get("Package") != name:
                continue
            arch = entry.get("indexArch")
            if arch not in ABIS or arch in selected or entry.get("Architecture") != arch:
                fail("Native component ABI selection is missing, duplicated or inconsistent: " + name)
            selected[arch] = package_version(entry.get("Version"))
            selected_strings.add(entry.get("Version"))
        if set(selected) != set(ABIS) or len(selected_strings) != 1:
            fail("Native component versions must match on both reviewed ABIs: " + name)
        versions[name] = next(iter(selected.values()))
    if versions["nodejs-lts"] != package_version(lock.get("node_version")):
        fail("Node version disagrees with the selected native packages")
    if versions["openssl"][:2] != (3, 5):
        code = "OPENSSL_36_EOL / OPENSSL_BRANCH_UNSUPPORTED" if versions["openssl"][:2] == (3, 6) else "OPENSSL_BRANCH_UNSUPPORTED"
        fail(code + ": selected OpenSSL branch lacks a supported compatible production policy")
    if today >= OPENSSL_35_EOL or versions["openssl"] < OPENSSL_35_PATCH_FLOOR:
        fail("OPENSSL_PATCH_OR_SUPPORT: supported OpenSSL 3.5 with the reviewed patch floor is required")
    if today < OPENSSL_35_FIX_AVAILABLE_FROM:
        fail("OPENSSL_FIX_NOT_AVAILABLE: announced December fix is not yet an available release")
    if versions["nodejs-lts"][0] != 24 or today >= NODE_24_EOL:
        fail("NODE_BRANCH_UNSUPPORTED: selected Node branch is outside the reviewed support window")
    if not SUPPORT_REVIEWED_ON <= today <= SUPPORT_REVIEW_UNTIL:
        fail("NATIVE_SUPPORT_REVIEW_STALE: refresh official lifecycle/advisory review before production")
    age = now - snapshot_time(lock)
    if age < timedelta(0) or age > timedelta(days=MAX_PRODUCTION_SNAPSHOT_DAYS):
        fail("NATIVE_SNAPSHOT_STALE: production requires a recent, non-future signed snapshot")


def verify_policy(lock, production=False, today=None):
    if lock.get("schema") != 1 or lock.get("node_version") != "24.22.3":
        fail("Unexpected native runtime policy")
    if type(lock.get("production_ready")) is not bool or not isinstance(lock.get("production_blockers"), list):
        fail("Native production approval state is missing")
    if lock["production_ready"] and lock["production_blockers"]:
        fail("Native production approval contradicts unresolved blockers")
    if production:
        verify_support_window(lock, today)
    if production and not lock["production_ready"]:
        blockers = "; ".join(entry["id"] + ": " + entry["reason"] for entry in lock["production_blockers"])
        fail("Production native runtime is blocked: " + (blockers or "review approval is absent"))


def verify_outputs(lock, apk=None):
    expected_abis = {v[0]: v[1] for v in ABIS.values()}
    if set(lock["outputs"]) != set(expected_abis):
        fail("Native output hashes are absent or incomplete; prepare and review the runtime lock first")
    maven_outputs = maven_native_inventory(lock)
    archive = zipfile.ZipFile(apk) if apk else None
    reports = []
    try:
        if archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                fail("APK contains duplicate ZIP entries")
            try:
                packaged_lock = json.loads(archive.read("assets/native-runtime/native-runtime.lock.json"))
            except (KeyError, ValueError):
                fail("APK is missing its native runtime provenance lock")
            if packaged_lock != lock:
                fail("APK native runtime provenance differs from the reviewed lock")
            present_abis = {name.split('/')[1] for name in archive.namelist() if name.startswith('lib/') and name.endswith('.so')}
            if not present_abis or not present_abis.issubset(expected_abis):
                fail("APK native ABI is missing or unexpected")
        else:
            present_abis = set(expected_abis)
            if {p.parent.name for p in JNI.glob("*/*.so")} != present_abis:
                fail("Native ABI inventory differs from the lock")
        for abi in sorted(present_abis):
            expected = dict(lock["outputs"][abi])
            libraries = {}
            if "libnode.so" not in expected or not expected:
                fail("Node runtime is missing from the output lock")
            if archive:
                expected.update(maven_outputs[abi])
                archive_paths = {name for name in archive.namelist() if name.startswith(f"lib/{abi}/") and name.endswith('.so')}
                if archive_paths != {f"lib/{abi}/{name}" for name in expected}:
                    fail("Native library inventory differs from the lock for " + abi)
            names = {Path(name).name for name in archive_paths} if archive else {p.name for p in (JNI / abi).glob('*.so')}
            if names != set(expected):
                fail("Native library inventory differs from the lock for " + abi)
            for name, checksum in expected.items():
                if not re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", name):
                    fail("Unsafe native library name")
                path = JNI / abi / name
                if not archive and (path.is_symlink() or path.parent.is_symlink()):
                    fail("Native library or ABI directory may not be a symlink")
                data = archive.read(f"lib/{abi}/{name}") if archive else path.read_bytes()
                if digest(data) != checksum or elf_machine(data) != expected_abis[abi]:
                    fail("Native hash or architecture mismatch: " + abi + "/" + name)
                libraries[name] = data
            reports.append(verify_linkage(libraries, set(lock["outputs"][abi]), abi))
        expected_notices = lock.get("license_outputs", {})
        if not expected_notices:
            fail("Native license manifest is missing")
        actual_notices = {name.removeprefix("assets/native-runtime/") for name in archive.namelist()
                          if name.startswith("assets/native-runtime/licenses/") and not name.endswith('/')} if archive else {
                              str(path.relative_to(ASSETS)) for path in (ASSETS / "licenses").rglob('*') if path.is_file()}
        if actual_notices != set(expected_notices):
            fail("Native license inventory differs from the lock")
        for name, checksum in expected_notices.items():
            if not name.startswith('licenses/') or '..' in Path(name).parts:
                fail("Unsafe native license path")
            data = archive.read("assets/native-runtime/" + name) if archive else (ASSETS / name).read_bytes()
            if digest(data) != checksum:
                fail("Native license hash mismatch: " + name)
    finally:
        if archive:
            archive.close()
    scope = "Node " + lock["node_version"] + (" and reviewed Maven" if apk else " local JNI")
    print("Verified pinned " + scope + " native bytes and static linkage for " + ", ".join(sorted(present_abis)))
    return reports


def prepare(lock, work, record):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        fail("The pinned repack toolchain currently supports Linux x86_64 build hosts")
    for command in ("gpg", "dpkg-deb", "readelf"):
        if not shutil.which(command):
            fail("Missing build tool: " + command)
    work.mkdir(parents=True, exist_ok=True)
    verify_provenance(lock, work)
    verify_maven_native_sources(lock, work)
    tool = lock["patchelf"]
    archive = fetch(tool["url"], work / "patchelf.tar.gz", tool["sha256"])
    patcher = work / "patchelf"
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == "patchelf"]
        if len(members) != 1:
            fail("Unexpected patchelf archive")
        binary = tar.extractfile(members[0]).read()
    if digest(binary) != tool["binary_sha256"]:
        fail("patchelf binary checksum mismatch")
    patcher.write_bytes(binary)
    patcher.chmod(0o755)
    if run(str(patcher), "--version").strip() != "patchelf " + tool["version"]:
        fail("patchelf version mismatch")
    packages = {p["Filename"]: p for p in lock["packages"]}
    def download(entry):
        filename = entry["Filename"]
        if filename.startswith('/') or '..' in Path(filename).parts:
            fail("Unsafe package path")
        return fetch(lock["repository"] + filename, work / "debs" / Path(filename).name, entry["SHA256"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(download, packages.values()))
    outputs = {}
    for arch, (abi, machine) in ABIS.items():
        with tempfile.TemporaryDirectory(prefix=arch + "-", dir=work) as directory:
            root = Path(directory) / "root"
            for entry in lock["packages"]:
                if entry["indexArch"] == arch:
                    # Data extraction only: no preinst/postinst/maintainer scripts execute.
                    run("dpkg-deb", "--extract", str(work / "debs" / Path(entry["Filename"]).name), str(root))
            prefix = root / "data/data/com.termux/files/usr"
            source = {"libnode.so": prefix / "bin/node"}
            pending = [source["libnode.so"]]
            while pending:
                current = pending.pop()
                for library in needed(current):
                    if library in SYSTEM_LIBS:
                        continue
                    if library not in NAMES:
                        fail("Unreviewed native dependency: " + library)
                    name = NAMES[library]
                    if name not in source:
                        candidate = (prefix / "lib" / library).resolve()
                        if not candidate.is_relative_to(prefix) or not candidate.is_file():
                            fail("Missing or unsafe native dependency: " + library)
                        source[name] = candidate
                        pending.append(candidate)
            target = Path(directory) / "jni"
            target.mkdir()
            for name, origin in sorted(source.items()):
                output = target / name
                data = origin.read_bytes()
                if elf_machine(data) != machine:
                    fail("Wrong ELF architecture in signed package")
                output.write_bytes(data)
                output.chmod(0o755)
                for old in needed(output):
                    if old in NAMES:
                        run(str(patcher), "--page-size", "16384", "--replace-needed", old, NAMES[old], str(output))
                if name != "libnode.so":
                    run(str(patcher), "--page-size", "16384", "--set-soname", name, str(output))
                run(str(patcher), "--page-size", "16384", "--set-rpath", "$ORIGIN", str(output))
                elf_machine(output.read_bytes())
                if any(lib not in SYSTEM_LIBS and lib not in source for lib in needed(output)):
                    fail("Repacked library has an unresolved dependency")
                if run(str(patcher), "--print-rpath", str(output)).strip() != "$ORIGIN":
                    fail("Unexpected native search path")
            prepared = {p.name: p.read_bytes() for p in sorted(target.glob("*.so"))}
            verify_linkage(prepared, set(prepared), abi)
            hashes = {name: digest(data) for name, data in prepared.items()}
            if not record and hashes != lock["outputs"].get(abi):
                fail("Rebuilt native hashes differ from the reviewed lock: " + abi)
            outputs[abi] = hashes
            destination = JNI / abi
            destination.mkdir(parents=True, exist_ok=True)
            for old in destination.glob("*.so"):
                old.unlink()
            for file in target.glob("*.so"):
                shutil.copy2(file, destination / file.name)
            notices = ASSETS / "licenses" / arch
            if notices.exists():
                shutil.rmtree(notices)
            notices.mkdir(parents=True, exist_ok=True)
            for file in (prefix / "share/doc").rglob("*"):
                if file.is_file() and file.name.lower() in {"copyright", "license", "license.txt", "copying"}:
                    if not file.resolve().is_relative_to(prefix):
                        fail("Package license points outside the extracted runtime")
                    relative = file.relative_to(prefix / "share/doc")
                    out = notices / relative
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(file, out)
            for file in (prefix / "share/LICENSES").glob("*"):
                if file.is_file():
                    out = notices / "shared" / file.name
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(file, out)
            for entry in lock.get("notice_overrides", []):
                source_notice = PROVENANCE / entry["filename"]
                if digest(source_notice.read_bytes()) != entry["sha256"]:
                    fail("Upstream supplemental license hash mismatch")
                destination_notice = notices / entry["destination"]
                if not destination_notice.resolve().is_relative_to(notices):
                    fail("Unsafe supplemental license destination")
                destination_notice.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_notice, destination_notice)
            for package in ("nodejs-lts", "libc++", "openssl", "c-ares", "libicu", "libsqlite", "zlib", "ca-certificates"):
                files = [p for p in (notices / package).glob('*') if p.is_file()]
                if not files or not any(p.stat().st_size > 100 for p in files):
                    fail("Required native license is missing or incomplete: " + package)
            print("Prepared " + abi + ": " + str(len(hashes)) + " pinned ELF files")
    license_hashes = {str(path.relative_to(ASSETS)): digest(path.read_bytes())
                      for path in sorted((ASSETS / "licenses").rglob('*')) if path.is_file()}
    if not record and license_hashes != lock.get("license_outputs"):
        fail("Rebuilt native license hashes differ from the reviewed lock")
    if record:
        lock["outputs"] = outputs
        lock["license_outputs"] = license_hashes
        LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
        print("Recorded output hashes; the native-runtime.lock.json diff requires review")
    assets = ASSETS
    assets.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(LOCK_PATH, assets / "native-runtime.lock.json")
    return verify_outputs(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "verify-apk"))
    parser.add_argument("--work", type=Path, default=ROOT / "build/native-runtime")
    parser.add_argument("--record-output-hashes", action="store_true")
    parser.add_argument("--production", action="store_true", help="Require reviewed production approval; there is no bypass for unresolved blockers")
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--report", type=Path, help="Write a per-ABI static linkage receipt; never a device/TLS acceptance result")
    args = parser.parse_args()
    receipt = {"schema": 1, "action": args.action, "status": "attempted",
               "scope": "static source/hash/ELF checks; no Android execution or TLS handshake"}
    def report():
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(receipt, indent=2) + "\n")
    report()
    try:
        lock = json.loads(LOCK_PATH.read_text())
        verify_policy(lock, args.production)
        if args.production:
            with tempfile.TemporaryDirectory(prefix="native-production-provenance-") as directory:
                verify_provenance(lock, Path(directory))
        if not lock["production_ready"]:
            print("Review runtime only: production approval is blocked by " + ", ".join(entry["id"] for entry in lock["production_blockers"]))
        if args.action == "prepare":
            abis = prepare(lock, args.work.resolve(), args.record_output_hashes)
        elif args.action == "verify-apk":
            if not args.apk:
                parser.error("verify-apk requires --apk")
            abis = verify_outputs(lock, args.apk)
        else:
            abis = verify_outputs(lock)
        receipt.update(status="passed", native_lock_sha256=digest(LOCK_PATH.read_bytes()),
                       node_version=lock["node_version"], abis=abis,
                       signed_provenance_checked_this_call=bool(args.production or args.action == "prepare"))
        report()
    except Exception as error:
        receipt.update(status="failed", error_type=type(error).__name__, reason=str(error))
        report()
        raise


if __name__ == "__main__":
    main()
