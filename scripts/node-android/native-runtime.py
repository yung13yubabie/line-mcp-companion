#!/usr/bin/env python3
"""Prepare and verify pinned Android runtimes without running package install scripts.

The committed signed APT snapshot authenticates every package hash. Default
prepare refuses changes to the reviewed output hashes. --record-output-hashes
is an explicit maintainer operation whose lockfile diff must be reviewed.
"""
import argparse
import concurrent.futures
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
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        fail("Expected a 64-bit little-endian ELF file")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or not count or count > 1024 or offset + size * count > len(data):
        fail("Invalid ELF program headers")
    load_segments = 0
    for index in range(count):
        start = offset + index * size
        if struct.unpack_from("<I", data, start)[0] == 1:
            load_segments += 1
            file_offset, virtual_address = struct.unpack_from("<QQ", data, start + 8)
            alignment = struct.unpack_from("<Q", data, start + 48)[0]
            if alignment < 16384 or file_offset % 16384 != virtual_address % 16384:
                fail("ELF load segment is not compatible with 16 KiB pages")
    if not load_segments:
        fail("ELF has no loadable segments")
    return struct.unpack_from("<H", data, 18)[0]


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


def verify_policy(lock, production=False):
    if lock.get("schema") != 1 or lock.get("node_version") != "24.22.3":
        fail("Unexpected native runtime policy")
    if type(lock.get("production_ready")) is not bool or not isinstance(lock.get("production_blockers"), list):
        fail("Native production approval state is missing")
    if lock["production_ready"] and lock["production_blockers"]:
        fail("Native production approval contradicts unresolved blockers")
    if production and not lock["production_ready"]:
        blockers = "; ".join(entry["id"] + ": " + entry["reason"] for entry in lock["production_blockers"])
        fail("Production native runtime is blocked: " + (blockers or "review approval is absent"))


def verify_outputs(lock, apk=None):
    expected_abis = {v[0]: v[1] for v in ABIS.values()}
    if set(lock["outputs"]) != set(expected_abis):
        fail("Native output hashes are absent or incomplete; prepare and review the runtime lock first")
    maven_outputs = maven_native_inventory(lock)
    archive = zipfile.ZipFile(apk) if apk else None
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
        for abi in present_abis:
            expected = dict(lock["outputs"][abi])
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
    print("Verified pinned " + scope + " native bytes for " + ", ".join(sorted(present_abis)))


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
            hashes = {p.name: digest(p.read_bytes()) for p in sorted(target.glob("*.so"))}
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
    verify_outputs(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "verify-apk"))
    parser.add_argument("--work", type=Path, default=ROOT / "build/native-runtime")
    parser.add_argument("--record-output-hashes", action="store_true")
    parser.add_argument("--production", action="store_true", help="Require reviewed production approval; there is no bypass for unresolved blockers")
    parser.add_argument("--apk", type=Path)
    args = parser.parse_args()
    lock = json.loads(LOCK_PATH.read_text())
    verify_policy(lock, args.production)
    if not lock["production_ready"]:
        print("Review runtime only: production approval is blocked by " + ", ".join(entry["id"] for entry in lock["production_blockers"]))
    if args.action == "prepare":
        prepare(lock, args.work.resolve(), args.record_output_hashes)
    elif args.action == "verify-apk":
        if not args.apk:
            parser.error("verify-apk requires --apk")
        verify_outputs(lock, args.apk)
    else:
        verify_outputs(lock)


if __name__ == "__main__":
    main()
