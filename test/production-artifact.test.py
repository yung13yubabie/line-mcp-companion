#!/usr/bin/env python3
"""Synthetic packaging structures only; positive fixtures are not real APK acceptance."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

SPEC = importlib.util.spec_from_file_location("boundary", Path(__file__).resolve().parents[1] / "scripts/production-artifact.py")
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)


def synthetic_dex(values):
    strings = [value.encode() for value in values]
    data = bytearray(112 + len(strings) * 4)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<II", data, 36, 112, 0x12345678)
    struct.pack_into("<II", data, 56, len(strings), 112)
    for i, value in enumerate(strings):
        struct.pack_into("<I", data, 112 + i * 4, len(data)); data += bytes([len(value)]) + value + b"\0"
    struct.pack_into("<I", data, 32, len(data))
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall); patch.object(gate, "ROOT", self.root).start()
        for name in ("scripts/bundle.ts", "src/main.ts", "src/runtime-mode.production.ts", "android/native-runtime.lock.json"):
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("synthetic source")
        self.lock = {"license_outputs": {"licenses/demo/copyright": gate.sha(b"synthetic license")}}
        (self.root / "android/native-runtime.lock.json").write_text(json.dumps(self.lock))
        self.data = b"console.log('synthetic production parser fixture');"
        self.receipt = {"schema": 1, "mode": "production", "bundle_sha256": gate.sha(self.data),
                        "recipe_sha256": gate.sha((self.root / "scripts/bundle.ts").read_bytes()),
                        "inputs": {name: gate.sha((self.root / name).read_bytes()) for name in ("src/main.ts", "src/runtime-mode.production.ts")}}
        self.args = argparse.Namespace(build_tools=self.root / "tools", expected_package="tw.linemcp.app.review", expected_version_code=5, expected_version_name="0.3.1-review", expected_abi="x86_64")
        self.badging = "package: name='tw.linemcp.app.review' versionCode='5' versionName='0.3.1-review'\nsdkVersion:'29'\ntargetSdkVersion:'35'\nnative-code: 'x86_64'\n"
        self.xml = "E: manifest (line=1)\n  E: application (line=2)\n"
        self.entries = {"assets/nodeapp/main.mjs": self.data, "assets/nodeapp/build-boundary.json": json.dumps(self.receipt).encode(),
                        "assets/native-runtime/native-runtime.lock.json": json.dumps(self.lock).encode(), "assets/native-runtime/licenses/demo/copyright": b"synthetic license",
                        "AndroidManifest.xml": b"synthetic binary manifest", "resources.arsc": b"synthetic resources", "classes.dex": synthetic_dex(["synthetic app", "MockAgent", "MockPool"]),
                        "DebugProbesKt.bin": b"synthetic dependency resource", "lib/x86_64/libnode.so": b"synthetic ELF; not execution"}

    def write_apk(self, entries=None):
        path = self.root / "synthetic.apk"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in (entries or self.entries).items(): archive.writestr(name, value)
        return path

    def inspect(self, entries=None):
        with patch.object(gate, "tool", side_effect=[self.badging, self.xml]):
            return gate.verify_apk(self.write_apk(entries), self.args)

    def test_synthetic_positive_and_library_mock_names_allowed(self):
        self.assertEqual(self.inspect()["dex_files"], 1)

    def test_markerless_app_stubs_and_activation_strings_rejected(self):
        for value in (b"class MockSource {}", b"async function goMockOnline() {}", b"LINE_MCP_MOCK", b"mock_mode", b"mock://local", b"mock-chat", b"mock-image"):
            with self.subTest(value=value), self.assertRaises(gate.Blocked): gate.scan(value, "synthetic")

    def test_unknown_extra_asset_even_without_marker_rejected(self):
        for value in (b"LMA_MOCK_DATA_v1", b"markerless fixture"):
            with self.subTest(value=value), self.assertRaises(gate.Blocked): self.inspect(self.entries | {"assets/extra.json": value})

    def test_marker_in_second_dex_and_resource_rejected(self):
        for additions in ({"classes2.dex": synthetic_dex(["mock_mode"])}, {"res/raw/demo.json": b"u_mock_demo"}):
            with self.subTest(additions=additions.keys()), self.assertRaises(gate.Blocked): self.inspect(self.entries | additions)

    def test_meta_inf_payload_is_scanned_without_blanket_exemption(self):
        for name, value in (("META-INF/extra.json", b"LMA_MOCK_DATA_v1"),
                            ("META-INF/services/com.example.Provider", b"class MockSource {}")):
            with self.subTest(name=name), self.assertRaises(gate.Blocked):
                self.inspect(self.entries | {name: value})

    def test_meta_inf_markerless_qa_fixture_and_test_paths_rejected(self):
        for name in ("META-INF/fixture.json", "META-INF/fixtures/notes.json", "META-INF/test-data.json",
                     "META-INF/qa/notes.json", "META-INF/Fixture.JSON"):
            with self.subTest(name=name), self.assertRaises(gate.Blocked):
                self.inspect(self.entries | {name: b"synthetic markerless metadata"})

    def test_legitimate_signature_and_dependency_metadata_names_allowed(self):
        # Synthetic contents test inventory/scanning only; no actual signature is asserted.
        metadata = {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
                    "META-INF/CERT.SF": b"Signature-Version: 1.0\r\n",
                    "META-INF/CERT.RSA": b"synthetic signature bytes, not a real signature",
                    "META-INF/kotlinx_coroutines_core.version": b"1.9.0",
                    "META-INF/services/com.example.MockAgent": b"undici MockAgent MockPool"}
        self.assertEqual(self.inspect(self.entries | metadata)["dex_files"], 1)

    def test_known_kotlin_toolchain_entries_allowed_but_contents_scanned(self):
        entries = self.entries | {name: b"synthetic dependency metadata" for name in gate.KOTLIN_METADATA_ENTRIES}
        self.assertEqual(self.inspect(entries)["dex_files"], 1)
        for name in ("kotlin-tooling-metadata.json", "kotlin/kotlin.kotlin_builtins"):
            with self.subTest(name=name), self.assertRaisesRegex(gate.Blocked, "App QA marker"):
                self.inspect(entries | {name: b"MockSource"})
        for name in ("kotlin/extra.json", "kotlin/other/other.kotlin_builtins",
                     "kotlin-tooling-metadata-copy.json"):
            with self.subTest(name=name), self.assertRaisesRegex(gate.Blocked, "Unknown APK entry"):
                self.inspect(entries | {name: b"synthetic unknown metadata"})

    def test_receipt_cannot_replace_final_bytes_scan(self):
        data = b"class MockSender {}"
        receipt = self.receipt | {"bundle_sha256": gate.sha(data)}
        with self.assertRaises(gate.Blocked): gate.verify_bundle(data, json.dumps(receipt))

    def test_receipt_hash_mode_closure_and_source_changes_fail_closed(self):
        for patching in ({"mode": "debug"}, {"bundle_sha256": "0" * 64}, {"inputs": {}}, {"inputs": self.receipt["inputs"] | {"src/mock/mock-stub.ts": "0" * 64}}, {"recipe_sha256": "0" * 64}):
            with self.subTest(patching=patching), self.assertRaises((gate.Blocked, OSError)): gate.verify_bundle(self.data, json.dumps(self.receipt | patching))
        (self.root / "src/main.ts").write_text("changed synthetic source")
        with self.assertRaises(gate.Blocked): gate.verify_bundle(self.data, json.dumps(self.receipt))

    def test_bad_dex_header_checksum_or_offset_rejected(self):
        good = self.entries["classes.dex"]
        for bad in (b"not DEX", good[:-1], good[:12] + b"x" + good[13:]):
            with self.subTest(length=len(bad)), self.assertRaises(gate.Blocked): gate.dex_strings(bad)

    def test_metadata_debug_test_version_package_abi_rejected(self):
        for badge in (self.badging + "sdkVersion:malformed\n", self.badging.replace("versionCode='5'", "versionCode='5' trailing"), self.badging + "application-debuggable\n", self.badging.replace("versionCode='5'", "versionCode='6'"), self.badging.replace("tw.linemcp.app.review", "other.app"), self.badging.replace("'x86_64'", "'arm64-v8a'")):
            with self.subTest(badge=badge), self.assertRaises(gate.Blocked): gate.metadata(badge, self.xml, "tw.linemcp.app.review", 5, "0.3.1-review", "x86_64")
        with self.assertRaises(gate.Blocked): gate.metadata(self.badging, self.xml + " A: android:testOnly(0x01010272)= (type 0x12)0xffffffff\n", "tw.linemcp.app.review", 5, "0.3.1-review", "x86_64")
        gate.metadata(self.badging, self.xml + " A: android:debuggable(0x0101000f)= (type 0x12)0x0\n", "tw.linemcp.app.review", 5, "0.3.1-review", "x86_64")

    def test_missing_required_assets_dex_and_unknown_entry_rejected(self):
        for name in ("assets/nodeapp/main.mjs", "assets/nodeapp/build-boundary.json", "classes.dex", "AndroidManifest.xml", "assets/native-runtime/licenses/demo/copyright"):
            with self.subTest(name=name), self.assertRaises((gate.Blocked, KeyError)): self.inspect({k: v for k, v in self.entries.items() if k != name})
        with self.assertRaises(gate.Blocked): self.inspect(self.entries | {"unexplained.json": b"fixture"})

    def test_report_aliases_and_symlinks_do_not_modify_artifact(self):
        apk = self.write_apk(); alias = self.root / "report.json"; alias.symlink_to(apk)
        with self.assertRaises(gate.Blocked): gate.report_safe(alias, apk, self.args.build_tools)
        alias.unlink(); alias.hardlink_to(apk)
        with self.assertRaises(gate.Blocked): gate.report_safe(alias, apk, self.args.build_tools)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
    print(f"Executed {result.testsRun}; skipped {len(result.skipped)}; failures {len(result.failures)}; errors {len(result.errors)}")
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)
