#!/usr/bin/env python3
"""Offline regression tests for native packaging trust boundaries.

These tests use synthetic ELF fixtures and the committed public signed snapshot;
they neither execute Android binaries nor contact any package server.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_runtime", ROOT / "scripts/node-android/native-runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def elf(machine, alignment=16384, file_offset=0, virtual_address=0):
    data = bytearray(128)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<QQ", data, 72, file_offset, virtual_address)
    struct.pack_into("<Q", data, 112, alignment)
    return bytes(data)


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
            data = elf(machine)
            (directory / "libnode.so").write_bytes(data)
            self.lock["outputs"][abi] = {"libnode.so": runtime.digest(data)}

    def verify(self, apk=None):
        with contextlib.redirect_stdout(io.StringIO()):
            runtime.verify_outputs(self.lock, apk)

    def maven_fixture(self, modified_arm64=False):
        libraries = {abi: elf(machine) + b"graphics-path" for abi, machine in runtime.ABIS.values()}
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

    def apk(self, entries=None, packaged_lock=True):
        output = self.directory / "test.apk"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w") as archive:
                for name, data in entries or [("lib/arm64-v8a/libnode.so", elf(183))]:
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
