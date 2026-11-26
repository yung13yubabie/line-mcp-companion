#!/usr/bin/env python3
"""Offline regression tests for native packaging trust boundaries.

These tests use synthetic ELF fixtures and the committed public signed snapshot;
they neither execute Android binaries nor contact any package server.
"""
import contextlib
import copy
from datetime import date, datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import sys
from unittest.mock import patch
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_runtime", ROOT / "scripts/node-android/native-runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def elf(machine, alignment=16384, file_offset=0, virtual_address=0, *,
        needed=("libtx_ssl.so", "libtx_crypto.so", "libc.so"), soname=None,
        search_path="$ORIGIN", interpreter="/system/bin/linker64", search_tag=29,
        version_needs=None, version_definitions=(), entry_point=None):
    """Synthetic ELF64 metadata fixture, never Android code and never executed."""
    strings = bytearray(b"\0")
    def text(value):
        offset = len(strings); strings.extend(value.encode("ascii") + b"\0"); return offset
    def version_hash(value):
        result = 0
        for byte in value.encode("ascii"):
            result = (result << 4) + byte
            high = result & 0xf0000000
            if high: result ^= high >> 24
            result &= ~high
        return result
    entries = [(1, text(name)) for name in needed]
    if soname is not None: entries.append((14, text(soname)))
    if search_path is not None: entries.append((search_tag, text(search_path)))
    definitions = bytearray()
    for index, definition in enumerate(version_definitions):
        names = [definition] if isinstance(definition, str) else list(definition)
        length = 20 + 8 * len(names)
        definitions.extend(struct.pack("<HHHHIII", 1, 0, index + 1, len(names), version_hash(names[0]), 20,
                                       length if index + 1 < len(version_definitions) else 0))
        for aux_index, name in enumerate(names):
            definitions.extend(struct.pack("<II", text(name), 8 if aux_index + 1 < len(names) else 0))
    needs = bytearray(); next_version_index = 2
    providers = list((version_needs or {}).items())
    for index, (provider, versions) in enumerate(providers):
        length = 16 + 16 * len(versions)
        needs.extend(struct.pack("<HHIII", 1, len(versions), text(provider), 16,
                                 length if index + 1 < len(providers) else 0))
        for aux_index, version in enumerate(versions):
            needs.extend(struct.pack("<IHHII", version_hash(version), 0, next_version_index, text(version),
                                     16 if aux_index + 1 < len(versions) else 0))
            next_version_index += 1
    if definitions: entries += [(0x6ffffffc, 4096), (0x6ffffffd, len(version_definitions))]
    if needs: entries += [(0x6ffffffe, 5120), (0x6fffffff, len(providers))]
    entries += [(5, 2048), (10, len(strings)), (0, 0)]
    data = bytearray(8192)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, machine, 1)
    struct.pack_into("<Q", data, 24, (512 if interpreter is not None else 0) if entry_point is None else entry_point)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 3 if interpreter is not None else 2)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, file_offset, virtual_address, 0, len(data), len(data), alignment)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 1024, 1024, 0, len(entries) * 16, len(entries) * 16, 8)
    if interpreter is not None:
        raw = interpreter.encode("ascii") + b"\0"
        data[768:768 + len(raw)] = raw
        struct.pack_into("<IIQQQQQQ", data, 176, 3, 4, 768, 768, 0, len(raw), len(raw), 1)
    for index, (tag, value) in enumerate(entries):
        struct.pack_into("<qQ", data, 1024 + index * 16, tag, value)
    assert len(strings) <= 2048 and len(definitions) <= 1024 and len(needs) <= 3072
    data[2048:2048 + len(strings)] = strings
    data[4096:4096 + len(definitions)] = definitions
    data[5120:5120 + len(needs)] = needs
    return bytes(data)


def appended_segments(data, segments):
    data = bytearray(data)
    count = struct.unpack_from("<H", data, 56)[0]
    for index, segment in enumerate(segments):
        struct.pack_into("<IIQQQQQQ", data, 64 + (count + index) * 56, *segment)
    struct.pack_into("<H", data, 56, count + len(segments))
    return bytes(data)


def dynamic_value(data, tag, value):
    data = bytearray(data)
    for offset in range(1024, 2048, 16):
        if struct.unpack_from("<q", data, offset)[0] == tag:
            struct.pack_into("<Q", data, offset + 8, value)
            return bytes(data)
    raise AssertionError("test fixture dynamic tag missing")


def tls_fixture(machine):
    return {
        "libnode.so": elf(machine),
        "libtx_ssl.so": elf(machine, needed=("libtx_crypto.so", "libc.so"), soname="libtx_ssl.so", interpreter=None),
        "libtx_crypto.so": elf(machine, needed=("libc.so",), soname="libtx_crypto.so", interpreter=None),
    }


class NativeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.original_jni = runtime.JNI
        runtime.JNI = self.directory / "jniLibs"
        self.addCleanup(setattr, runtime, "JNI", self.original_jni)
        self.original_assets = runtime.ASSETS
        runtime.ASSETS = self.directory / "assets"
        self.addCleanup(setattr, runtime, "ASSETS", self.original_assets)
        (runtime.ASSETS / "licenses").mkdir(parents=True)
        (runtime.ASSETS / "licenses/NOTICE.txt").write_bytes(b"synthetic notice")
        self.lock = {"node_version": "24.22.3", "outputs": {}, "maven_native_artifacts": [], "license_outputs": {
            "licenses/NOTICE.txt": runtime.digest(b"synthetic notice")}}
        for abi, machine in runtime.ABIS.values():
            directory = runtime.JNI / abi
            directory.mkdir(parents=True)
            files = tls_fixture(machine)
            for name, data in files.items(): (directory / name).write_bytes(data)
            self.lock["outputs"][abi] = {name: runtime.digest(data) for name, data in files.items()}

    def verify(self, apk=None):
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.verify_outputs(self.lock, apk)

    def maven_fixture(self, modified_arm64=False):
        libraries = {abi: elf(machine, needed=("libc.so",), soname="libandroidx.graphics.path.so",
                              search_path=None, interpreter=None) + b"graphics-path" for abi, machine in runtime.ABIS.values()}
        aar = self.directory / "maven/graphics-path-1.0.1.aar"
        aar.parent.mkdir(exist_ok=True)
        with zipfile.ZipFile(aar, "w") as archive:
            for abi, data in libraries.items():
                if modified_arm64 and abi == 'arm64-v8a':
                    data += b"tampered"
                archive.writestr(f"jni/{abi}/libandroidx.graphics.path.so", data)
        self.lock["maven_native_artifacts"] = [{
            "coordinate": "androidx.graphics:graphics-path:1.0.1",
            "url": "https://dl.google.com/dl/android/maven2/androidx/graphics/graphics-path/1.0.1/graphics-path-1.0.1.aar",
            "sha256": runtime.digest(aar.read_bytes()),
            "outputs": {abi: {"libandroidx.graphics.path.so": runtime.digest(data)} for abi, data in libraries.items()},
        }]
        return libraries

    def apk(self, entries=None, packaged_lock=True, include_tls=True):
        entries = list(entries if entries is not None else [("lib/arm64-v8a/libnode.so", elf(183))])
        if include_tls:
            names = {name for name, _ in entries}
            for arch, (abi, machine) in runtime.ABIS.items():
                if f"lib/{abi}/libnode.so" in names:
                    entries.extend((f"lib/{abi}/{name}", data) for name, data in tls_fixture(machine).items()
                                   if name != "libnode.so" and f"lib/{abi}/{name}" not in names)
        output = self.directory / "test.apk"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w") as archive:
                for name, data in entries:
                    archive.writestr(name, data)
                if packaged_lock:
                    archive.writestr("assets/native-runtime/native-runtime.lock.json", json.dumps(self.lock))
                archive.writestr("assets/native-runtime/licenses/NOTICE.txt", b"synthetic notice")
        return output

    def test_both_reviewed_abis_are_accepted(self):
        self.verify()

    def test_missing_abi_is_rejected(self):
        shutil.rmtree(runtime.JNI / "x86_64")
        with self.assertRaisesRegex(RuntimeError, "ABI inventory"):
            self.verify()

    def test_extra_abi_is_rejected(self):
        (runtime.JNI / "armeabi-v7a").mkdir()
        (runtime.JNI / "armeabi-v7a/libextra.so").write_bytes(elf(183))
        with self.assertRaisesRegex(RuntimeError, "ABI inventory"):
            self.verify()

    def test_extra_library_is_rejected(self):
        (runtime.JNI / "x86_64/libextra.so").write_bytes(elf(62))
        with self.assertRaisesRegex(RuntimeError, "library inventory"):
            self.verify()

    def test_modified_library_is_rejected(self):
        (runtime.JNI / "arm64-v8a/libnode.so").write_bytes(elf(183) + b"tampered")
        with self.assertRaisesRegex(RuntimeError, "hash or architecture"):
            self.verify()

    def test_wrong_architecture_is_rejected_even_if_hash_matches(self):
        data = elf(62)
        (runtime.JNI / "arm64-v8a/libnode.so").write_bytes(data)
        self.lock["outputs"]["arm64-v8a"]["libnode.so"] = runtime.digest(data)
        with self.assertRaisesRegex(RuntimeError, "hash or architecture"):
            self.verify()

    def test_symlinked_library_is_rejected(self):
        target = runtime.JNI / "arm64-v8a/libnode.so"
        external = self.directory / "external.so"
        target.rename(external)
        target.symlink_to(external)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.verify()

    def test_symlinked_abi_directory_is_rejected(self):
        target = runtime.JNI / "arm64-v8a"
        external = self.directory / "external-abi"
        target.rename(external)
        target.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.verify()

    def test_4k_alignment_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "16 KiB"):
            runtime.elf_machine(elf(183, alignment=4096))

    def test_16k_alignment_with_incongruent_offsets_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "16 KiB"):
            runtime.elf_machine(elf(183, file_offset=4096))

    def test_truncated_elf_headers_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "program headers"):
            runtime.elf_machine(elf(183)[:80])

    def test_split_apk_with_provenance_is_accepted(self):
        self.verify(self.apk())

    def test_apk_without_provenance_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "provenance lock"):
            self.verify(self.apk(packaged_lock=False))

    def test_apk_without_native_runtime_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "ABI is missing"):
            self.verify(self.apk(entries=[("assets/file", b"data")]))

    def test_duplicate_apk_library_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate ZIP"):
            self.verify(self.apk(entries=[("lib/arm64-v8a/libnode.so", elf(183))] * 2))

    def test_apk_with_stale_provenance_is_rejected(self):
        apk = self.apk()
        self.lock["node_version"] = "changed"
        with self.assertRaisesRegex(RuntimeError, "provenance differs"):
            self.verify(apk)

    def test_apk_with_exact_reviewed_maven_library_is_accepted(self):
        libraries = self.maven_fixture()
        self.verify(self.apk(entries=[("lib/arm64-v8a/libnode.so", elf(183)),
            ("lib/arm64-v8a/libandroidx.graphics.path.so", libraries['arm64-v8a'])]))

    def test_apk_with_tampered_maven_library_is_rejected(self):
        libraries = self.maven_fixture()
        with self.assertRaisesRegex(RuntimeError, "hash or architecture"):
            self.verify(self.apk(entries=[("lib/arm64-v8a/libnode.so", elf(183)),
                ("lib/arm64-v8a/libandroidx.graphics.path.so", libraries['arm64-v8a'] + b"tampered")]))

    def test_apk_missing_reviewed_maven_library_is_rejected(self):
        self.maven_fixture()
        with self.assertRaisesRegex(RuntimeError, "library inventory"):
            self.verify(self.apk())

    def test_apk_with_unknown_extra_library_is_rejected(self):
        libraries = self.maven_fixture()
        with self.assertRaisesRegex(RuntimeError, "library inventory"):
            self.verify(self.apk(entries=[("lib/arm64-v8a/libnode.so", elf(183)),
                ("lib/arm64-v8a/libandroidx.graphics.path.so", libraries['arm64-v8a']),
                ("lib/arm64-v8a/libunknown.so", elf(183))]))

    def test_local_jni_inventory_keeps_maven_libraries_separate(self):
        libraries = self.maven_fixture()
        self.verify()
        (runtime.JNI / "arm64-v8a/libandroidx.graphics.path.so").write_bytes(libraries['arm64-v8a'])
        with self.assertRaisesRegex(RuntimeError, "library inventory"):
            self.verify()

    def test_maven_source_verification_does_not_copy_libraries(self):
        self.maven_fixture()
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.verify_maven_native_sources(self.lock, self.directory)
        self.assertFalse((runtime.JNI / "arm64-v8a/libandroidx.graphics.path.so").exists())
        self.verify()

    def test_maven_elf_hash_is_checked_even_with_matching_aar_hash(self):
        self.maven_fixture(modified_arm64=True)
        with self.assertRaisesRegex(RuntimeError, "Maven AAR native hash"):
            runtime.verify_maven_native_sources(self.lock, self.directory)

    def test_missing_license_is_rejected(self):
        (runtime.ASSETS / "licenses/NOTICE.txt").unlink()
        with self.assertRaisesRegex(RuntimeError, "license inventory"):
            self.verify()

    def test_modified_license_is_rejected(self):
        (runtime.ASSETS / "licenses/NOTICE.txt").write_bytes(b"404: Not Found")
        with self.assertRaisesRegex(RuntimeError, "license hash mismatch"):
            self.verify()

    def test_cached_download_tampering_is_rejected_without_network(self):
        cached = self.directory / "cached.deb"
        cached.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "Cached SHA-256 mismatch"):
            runtime.fetch("https://invalid.example/not-contacted", cached, runtime.digest(b"original"))

    def replace_reviewed_elf(self, name, data, abi="arm64-v8a"):
        (runtime.JNI / abi / name).write_bytes(data)
        self.lock["outputs"][abi][name] = runtime.digest(data)

    def test_matching_hash_does_not_replace_node_direct_tls_contract(self):
        self.replace_reviewed_elf("libnode.so", elf(183, needed=("libtx_crypto.so", "libc.so")))
        with self.assertRaisesRegex(RuntimeError, "Node direct TLS"):
            self.verify()

    def test_matching_hash_does_not_replace_ssl_to_crypto_contract(self):
        self.replace_reviewed_elf("libtx_ssl.so", elf(183, needed=("libc.so",), soname="libtx_ssl.so", interpreter=None))
        with self.assertRaisesRegex(RuntimeError, "TLS crypto edge"):
            self.verify()

    def test_matching_hash_does_not_replace_dependency_closure(self):
        self.replace_reviewed_elf("libtx_ssl.so", elf(183, needed=("libtx_crypto.so", "libmissing.so"), soname="libtx_ssl.so", interpreter=None))
        with self.assertRaisesRegex(RuntimeError, "unresolved dependency"):
            self.verify()

    def test_matching_hash_does_not_replace_soname_contract(self):
        self.replace_reviewed_elf("libtx_ssl.so", elf(183, needed=("libtx_crypto.so",), soname="libssl.so.3", interpreter=None))
        with self.assertRaisesRegex(RuntimeError, "SONAME"):
            self.verify()

    def test_matching_hash_does_not_replace_search_path_contract(self):
        self.replace_reviewed_elf("libnode.so", elf(183, search_path="/data/data/com.termux/files/usr/lib"))
        with self.assertRaisesRegex(RuntimeError, "search path"):
            self.verify()

    def test_matching_hash_does_not_replace_android_interpreter_contract(self):
        self.replace_reviewed_elf("libnode.so", elf(183, interpreter="/system/bin/linker"))
        with self.assertRaisesRegex(RuntimeError, "interpreter"):
            self.verify()

    def versioned_tls_fixture(self, crypto_definitions=("OPENSSL_3.0.0", "OPENSSL_3.6.0"), ssl_definitions=("OPENSSL_3.0.0",)):
        self.replace_reviewed_elf("libtx_crypto.so", elf(183, needed=("libc.so",), soname="libtx_crypto.so", interpreter=None,
                                                       version_definitions=crypto_definitions))
        self.replace_reviewed_elf("libtx_ssl.so", elf(183, needed=("libtx_crypto.so", "libc.so"), soname="libtx_ssl.so", interpreter=None,
                                                    version_needs={"libtx_crypto.so": ["OPENSSL_3.6.0"]}, version_definitions=ssl_definitions))

    def test_exact_provider_version_requirements_are_satisfied(self):
        self.versioned_tls_fixture()
        self.verify()

    def test_crypto_version_cannot_be_supplied_by_another_library(self):
        self.versioned_tls_fixture(crypto_definitions=("OPENSSL_3.0.0",), ssl_definitions=("OPENSSL_3.0.0", "OPENSSL_3.6.0"))
        with self.assertRaisesRegex(RuntimeError, "provider version"):
            self.verify()

    def test_verdef_parent_aux_is_not_a_definition(self):
        self.versioned_tls_fixture(crypto_definitions=(("UNRELATED_VERSION", "OPENSSL_3.6.0"),))
        with self.assertRaisesRegex(RuntimeError, "provider version"):
            self.verify()

    def test_version_provider_must_be_a_direct_needed_library(self):
        self.replace_reviewed_elf("libnode.so", elf(183, version_needs={"libundeclared.so": ["SYNTHETIC_VERSION"]}))
        with self.assertRaisesRegex(RuntimeError, "version provider.*NEEDED"):
            self.verify()

    def test_node_entry_must_be_executable_and_file_backed(self):
        for entry in (0, 100000):
            with self.subTest(entry=entry):
                self.replace_reviewed_elf("libnode.so", elf(183, entry_point=entry))
                with self.assertRaisesRegex(RuntimeError, "Node entry"):
                    self.verify()

    def test_shared_library_entry_must_be_zero(self):
        self.replace_reviewed_elf("libtx_ssl.so", elf(183, needed=("libtx_crypto.so",), soname="libtx_ssl.so", interpreter=None, entry_point=512))
        with self.assertRaisesRegex(RuntimeError, "Shared library.*entry"):
            self.verify()

    def test_node_entry_cannot_point_to_nonexecutable_load(self):
        data = bytearray(elf(183)); struct.pack_into("<I", data, 68, 4)
        self.replace_reviewed_elf("libnode.so", bytes(data))
        with self.assertRaisesRegex(RuntimeError, "Node entry"):
            self.verify()

    def test_non_system_version_name_hidden_bit_is_masked(self):
        self.versioned_tls_fixture()
        data = bytearray((runtime.JNI / "arm64-v8a/libtx_ssl.so").read_bytes())
        struct.pack_into("<H", data, 5120 + 16 + 6, 0x8002)
        self.replace_reviewed_elf("libtx_ssl.so", bytes(data))
        self.verify()

    def test_version_table_pointer_must_be_file_backed(self):
        data = elf(183, version_needs={"libtx_crypto.so": ["OPENSSL_3.6.0"]})
        self.replace_reviewed_elf("libnode.so", dynamic_value(data, 0x6ffffffe, 999999))
        with self.assertRaisesRegex(RuntimeError, "file-backed LOAD"):
            self.verify()

    def test_version_chain_count_requires_real_terminating_chain(self):
        data = elf(183, version_needs={"libtx_crypto.so": ["OPENSSL_3.6.0"]})
        self.replace_reviewed_elf("libnode.so", dynamic_value(data, 0x6fffffff, 2))
        with self.assertRaisesRegex(RuntimeError, "version chain"):
            self.verify()

    def test_dynamic_segment_requires_consistent_file_backed_virtual_mapping(self):
        for field, value in ((136, 0x7fff000000000000), (136, 1040), (160, 1)):
            with self.subTest(field=field, value=value):
                data = bytearray(elf(183))
                struct.pack_into("<Q", data, field, value)
                self.replace_reviewed_elf("libnode.so", bytes(data))
                with self.assertRaisesRegex(RuntimeError, "ELF.*(mapping|dynamic|memory)"):
                    self.verify()

    def test_malformed_dynamic_string_pointer_fails_closed(self):
        self.replace_reviewed_elf("libnode.so", dynamic_value(elf(183), 5, 999999))
        with self.assertRaisesRegex(RuntimeError, "file-backed LOAD"):
            self.verify()

    def test_16k_relro_padding_can_extend_beyond_writable_load(self):
        # Mirrors the shape of valid AndroidX padding, not any real executable.
        data = appended_segments(elf(183), [
            (1, 6, 0x1c40, 0x5c40, 0, 0x390, 0x390, 0x4000),
            (1, 6, 0x1fd0, 0x9fd0, 0, 0x10, 0x10, 0x4000),
            (0x6474e552, 4, 0x1c40, 0x5c40, 0, 0x3c0, 0x3c0, 1),
        ])
        self.assertEqual(runtime.elf_machine(data), 183)

    def test_16k_relro_checks_bss_after_end_in_same_load(self):
        data = appended_segments(elf(183), [
            (1, 6, 0x1c40, 0x5c40, 0, 0x390, 0x3d0, 0x4000),
            (0x6474e552, 4, 0x1c40, 0x5c40, 0, 0x3c0, 0x3c0, 1),
        ])
        with self.assertRaisesRegex(RuntimeError, "RELRO protection tail"):
            runtime.elf_machine(data)

    def test_16k_relro_checks_other_writable_loads_in_roundup_page(self):
        data = appended_segments(elf(183), [
            (1, 6, 0x1c40, 0x5c40, 0, 0x390, 0x390, 0x4000),
            (1, 6, 0x2000, 0x6000, 0, 0, 0x10, 0x4000),
            (0x6474e552, 4, 0x1c40, 0x5c40, 0, 0x3c0, 0x3c0, 1),
        ])
        with self.assertRaisesRegex(RuntimeError, "RELRO protection tail"):
            runtime.elf_machine(data)

    def test_16k_relro_aligned_end_and_absent_relro_are_accepted(self):
        self.assertEqual(runtime.elf_machine(elf(183)), 183)
        data = appended_segments(elf(183), [
            (1, 6, 0, 0x4000, 0, 0x2000, 0x4000, 0x4000),
            (0x6474e552, 4, 0, 0x4000, 0, 0x2000, 0x4000, 1),
        ])
        self.assertEqual(runtime.elf_machine(data), 183)

    def test_linkage_receipt_records_metadata_and_replaces_stale_success_on_failure(self):
        self.lock.update(schema=1, production_ready=False, production_blockers=[])
        path = self.directory / "lock.json"; report = self.directory / "report.json"
        path.write_text(json.dumps(self.lock))
        with patch.object(runtime, "LOCK_PATH", path), patch.object(sys, "argv", [str(runtime.__file__), "verify", "--report", str(report)]), contextlib.redirect_stdout(io.StringIO()):
            runtime.main()
            first = json.loads(report.read_text())
            self.assertEqual(first["status"], "passed")
            self.assertEqual(len(first["abis"]), 2)
            self.assertFalse(first["signed_provenance_checked_this_call"])
            self.assertEqual(first["abis"][0]["platform_symbol_versions_and_dynsym_resolution"], "not_validated_by_this_static_gate")
            self.replace_reviewed_elf("libnode.so", elf(183, search_path="/unexpected"))
            path.write_text(json.dumps(self.lock))
            with self.assertRaisesRegex(RuntimeError, "search path"):
                runtime.main()
        failed = json.loads(report.read_text())
        self.assertEqual(failed["status"], "failed")
        self.assertNotIn("abis", failed, "a failed call cannot retain an earlier successful ABI receipt")

    def test_apk_cli_records_only_packaged_abi_and_checks_the_same_graph(self):
        self.lock.update(schema=1, production_ready=False, production_blockers=[])
        path = self.directory / "lock.json"; report = self.directory / "apk-report.json"
        path.write_text(json.dumps(self.lock)); apk = self.apk()
        with patch.object(runtime, "LOCK_PATH", path), patch.object(sys, "argv", [str(runtime.__file__), "verify-apk", "--apk", str(apk), "--report", str(report)]), contextlib.redirect_stdout(io.StringIO()):
            runtime.main()
        result = json.loads(report.read_text())
        self.assertEqual(result["status"], "passed")
        self.assertEqual([item["abi"] for item in result["abis"]], ["arm64-v8a"])
        self.assertTrue(result["abis"][0]["node_direct_tls"])

    def test_committed_policy_blocks_production(self):
        lock = json.loads(runtime.LOCK_PATH.read_text())
        runtime.verify_policy(lock)
        with self.assertRaisesRegex(RuntimeError, "OPENSSL_36_EOL"):
            runtime.verify_policy(lock, production=True)

    def test_removing_approval_state_does_not_bypass_production_gate(self):
        lock = json.loads(runtime.LOCK_PATH.read_text())
        del lock["production_ready"]
        with self.assertRaisesRegex(RuntimeError, "approval state is missing"):
            runtime.verify_policy(lock, production=True)

    def test_flipping_approval_cannot_approve_eol_openssl(self):
        lock = json.loads(runtime.LOCK_PATH.read_text())
        lock["production_ready"] = True
        lock["production_blockers"] = []
        with self.assertRaisesRegex(RuntimeError, "OPENSSL_BRANCH_UNSUPPORTED"):
            runtime.verify_policy(lock, production=True)

    def supported_policy_fixture(self):
        # Pure lifecycle fixture only; not a real available/signed Android package.
        lock = json.loads(runtime.LOCK_PATH.read_text())
        lock["production_ready"] = True
        lock["production_blockers"] = []
        for entry in lock["packages"]:
            if entry["Package"] == "openssl":
                entry["Version"] = "1:3.5.10"
        return lock

    def test_synthetic_lifecycle_candidate_is_only_a_necessary_policy_condition(self):
        runtime.verify_policy(self.supported_policy_fixture(), production=True, today=date(2026, 12, 2))

    def test_announced_fix_is_not_treated_as_available_before_release(self):
        with self.assertRaisesRegex(RuntimeError, "OPENSSL_FIX_NOT_AVAILABLE"):
            runtime.verify_policy(self.supported_policy_fixture(), production=True, today=date(2026, 11, 26))

    def test_older_openssl_patch_is_rejected_on_supported_branch(self):
        lock = self.supported_policy_fixture()
        for entry in lock["packages"]:
            if entry["Package"] == "openssl":
                entry["Version"] = "1:3.5.9"
        with self.assertRaisesRegex(RuntimeError, "OPENSSL_PATCH_OR_SUPPORT"):
            runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_unknown_major_and_eol_branch_cannot_inherit_approval(self):
        for version in ("1:3.6.5", "4.1.1", "99.0.0"):
            with self.subTest(version=version):
                lock = self.supported_policy_fixture()
                for entry in lock["packages"]:
                    if entry["Package"] == "openssl": entry["Version"] = version
                with self.assertRaisesRegex(RuntimeError, "OPENSSL_BRANCH_UNSUPPORTED"):
                    runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_lifecycle_review_expiry_rejects_stale_and_clock_rollback(self):
        for when in (date(2026, 12, 27), date(2025, 12, 2)):
            with self.subTest(when=when):
                with self.assertRaises(RuntimeError):
                    runtime.verify_policy(self.supported_policy_fixture(), production=True, today=when)

    def test_snapshot_age_and_future_snapshot_are_rejected(self):
        for timestamp in ("2026-10-01T07:12:38Z", "2026-12-03T07:12:38Z"):
            with self.subTest(timestamp=timestamp):
                lock = self.supported_policy_fixture(); lock["snapshot_date"] = timestamp
                with self.assertRaisesRegex(RuntimeError, "NATIVE_SNAPSHOT_STALE"):
                    runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_snapshot_timestamp_boundaries_use_actual_utc_instants(self):
        lock = self.supported_policy_fixture()
        lock["snapshot_date"] = "2026-11-02T00:00:00Z"
        runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))
        for timestamp in ("2026-11-01T23:59:59Z", "2026-12-02T00:00:01Z"):
            with self.subTest(timestamp=timestamp):
                lock["snapshot_date"] = timestamp
                with self.assertRaisesRegex(RuntimeError, "NATIVE_SNAPSHOT_STALE"):
                    runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_missing_malformed_or_timezone_free_snapshot_fails_closed(self):
        for timestamp in (None, "2026-11-25T07:12:38", "not-a-date"):
            with self.subTest(timestamp=timestamp):
                lock = self.supported_policy_fixture(); lock["snapshot_date"] = timestamp
                with self.assertRaisesRegex(RuntimeError, "snapshot_date"):
                    runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_component_selection_requires_both_matching_abis(self):
        for mutate in ("missing", "duplicate", "mismatch", "revision", "architecture"):
            with self.subTest(mutate=mutate):
                lock = self.supported_policy_fixture()
                openssl = [x for x in lock["packages"] if x["Package"] == "openssl"]
                if mutate == "missing": lock["packages"].remove(openssl[0])
                elif mutate == "duplicate": lock["packages"].append(copy.deepcopy(openssl[0]))
                elif mutate == "mismatch": openssl[0]["Version"] = "1:3.5.11"
                elif mutate == "revision": openssl[0]["Version"] = "1:3.5.10-2"
                else: openssl[0]["Architecture"] = "wrong"
                with self.assertRaisesRegex(RuntimeError, "ABI"):
                    runtime.verify_policy(lock, production=True, today=date(2026, 12, 2))

    def test_prerelease_or_unparseable_versions_are_rejected(self):
        for version in ("1:3.5.10~beta1", "3.5.10-rc1", "3.5", "future"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(RuntimeError, "stable reviewed format"):
                    runtime.package_version(version)
        self.assertEqual(runtime.package_version("1:3.5.10-2"), (3, 5, 10))

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is required for signed snapshot tests")
    def test_lock_cannot_relabel_signed_snapshot_date(self):
        lock = json.loads(runtime.LOCK_PATH.read_text())
        lock["snapshot_date"] = "2026-11-26T07:12:38Z"
        with self.assertRaisesRegex(RuntimeError, "snapshot_date does not match signed metadata"):
            runtime.verify_provenance(lock, self.directory)

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is required for signed snapshot tests")
    def test_production_cli_rechecks_signed_source_before_output_verification(self):
        lock = self.supported_policy_fixture()
        path = self.directory / "candidate.json"; path.write_text(json.dumps(lock))
        class AfterAnnouncedRelease(datetime):
            @classmethod
            def now(cls, tz=None): return cls(2026, 12, 2, tzinfo=timezone.utc)
        # Standard main() entry, fixed test clock only. The synthetic candidate
        # passes lifecycle metadata but must fail real signed package provenance.
        with patch.object(runtime, "LOCK_PATH", path), patch.object(runtime, "datetime", AfterAnnouncedRelease), patch.object(sys, "argv", [str(runtime.__file__), "verify", "--production"]):
            with self.assertRaisesRegex(RuntimeError, "selection does not match signed metadata"):
                runtime.main()

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is required for signed snapshot tests")
    def test_signed_package_version_cannot_be_relabelled(self):
        lock = json.loads(runtime.LOCK_PATH.read_text())
        lock["packages"][0]["Version"] = "999.0.0"
        with self.assertRaisesRegex(RuntimeError, "selection does not match signed metadata"):
            runtime.verify_provenance(lock, self.directory)

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is required for signed snapshot tests")
    def test_committed_snapshot_signature_and_hash_chain_are_valid(self):
        runtime.verify_provenance(json.loads(runtime.LOCK_PATH.read_text()), self.directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
