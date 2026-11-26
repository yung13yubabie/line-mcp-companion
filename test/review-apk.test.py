#!/usr/bin/env python3
"""Synthetic parser/decision/file-race tests only; no APK signing, install or device test.
The tool runner is replaced only in wrapper tests. Root separately checks real APKs.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("review_apk", ROOT / "scripts/review-apk.py")
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)

SIG = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate SHA-256 digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"""
BADGING = """package: name='tw.linemcp.app.review' versionCode='5' versionName='0.3.1-review'
sdkVersion:'29'
targetSdkVersion:'35'
application-label:'Synthetic Review metadata'
native-code: 'x86_64'
"""


class ReviewApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"; self.tools.mkdir()
        for name in ("apksigner", "aapt"):
            path = self.tools / name; path.write_text("synthetic stub; never executed\n"); path.chmod(0o755)
        self.apk = self.root / "synthetic.apk"; self.apk.write_bytes(b"synthetic parser fixture, not a valid APK")

    def fake_tool(self, tool, args):
        return {"exit_code": 0, "output": SIG if tool.name == "apksigner" else BADGING}

    def test_complete_synthetic_parser_fields(self):
        item = review.parse_inspection(SIG, BADGING)
        self.assertEqual(item["package"], "tw.linemcp.app.review")
        self.assertEqual(item["versionCode"], 5)
        self.assertEqual(item["versionName"], "0.3.1-review")
        self.assertEqual((item["minSDK"], item["targetSDK"], item["abi"]), (29, 35, "x86_64"))
        self.assertEqual(item["certificate_sha256"], "a" * 64)
        self.assertTrue(item["schemes"]["v2"])
        self.assertFalse(item["debuggable"])

    def test_rejects_nonreview_debuggable_split_and_ambiguous_badging(self):
        for text in (
            BADGING.replace("tw.linemcp.app.review", "tw.linemcp.app"),
            BADGING.replace("0.3.1-review", "0.3.1"),
            BADGING + "application-debuggable\n",
            BADGING.replace("versionCode='5'", "versionCode='5' split='config.x86_64'"),
            BADGING.replace("versionCode='5'", "versionCode='5' versionCodeMajor='1'"),
            BADGING.replace("versionCode='5'", "versionCode='5' versionCode='6'"),
            BADGING.replace("versionCode='5'", "versionCode='five'"),
            BADGING.replace("versionCode='5'", "versionCode='2147483648'"),
            BADGING.replace("native-code: 'x86_64'", "native-code: 'x86_64' 'arm64-v8a'"),
            BADGING.replace("native-code: 'x86_64'", "native-code: 'unknown'"),
            BADGING + "sdkVersion:'29'\n",
            BADGING + "sdkVersion:malformed\n",
            BADGING + "native-code: malformed\n",
            BADGING.replace("targetSdkVersion:'35'\n", ""),
            BADGING.replace("sdkVersion:'29'", "sdkVersion:'FutureSdk'"),
            BADGING.replace("targetSdkVersion:'35'", "targetSdkVersion:'28'"),
        ):
            with self.subTest(text=text), self.assertRaises(review.Blocked):
                review.parse_inspection(SIG, text)

    def test_rejects_missing_duplicate_unknown_or_multiple_signers(self):
        for text in (
            SIG.replace("Verifies\n", "DOES NOT VERIFY\n"),
            SIG.replace("Number of signers: 1", "Number of signers: 2"),
            SIG + "Signer #2 certificate SHA-256 digest: " + "b" * 64 + "\n",
            SIG + "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n",
            SIG.replace("A" * 64, "A" * 63),
            SIG.replace("v2): true", "v2): false"),
            SIG.replace("Number of signers: 1\n", ""),
            SIG + "Number of signers: 1\n",
            SIG + "Verified using v2 scheme malformed\n",
            SIG + "Verified using v4 scheme malformed\n",
            SIG + "Verified using v5 scheme (unknown): true\n",
            SIG + "Signer #unknown certificate SHA-256 digest: " + "b" * 64 + "\n",
            SIG.replace("Verified using v3 scheme (APK Signature Scheme v3): false\n", ""),
            SIG + "Proof-of-rotation: present\n",
        ):
            with self.subTest(text=text), self.assertRaises(review.Blocked):
                review.parse_inspection(text, BADGING)

    def test_metadata_eligibility_is_strictly_increasing_not_versionname_order(self):
        base = review.parse_inspection(SIG, BADGING)
        candidate = copy.deepcopy(base); candidate["versionCode"] = 6; candidate["versionName"] = "0.0.1-review"
        self.assertEqual(review.compare_conditions(base, candidate), [])
        for code in (5, 4):
            candidate["versionCode"] = code
            self.assertIn("version_not_advanced", review.compare_conditions(base, candidate))

    def test_comparison_aggregates_signer_version_and_abi_reasons(self):
        base = review.parse_inspection(SIG, BADGING)
        candidate = copy.deepcopy(base); candidate["certificate_sha256"] = "b" * 64; candidate["abi"] = "arm64-v8a"
        self.assertEqual(set(review.compare_conditions(base, candidate)), {"signer_mismatch", "version_not_advanced", "abi_mismatch"})

    def test_synthetic_wrapper_hashes_before_and_after_both_tools(self):
        with patch.object(review, "run_tool", side_effect=self.fake_tool) as runner:
            item = review.inspect_apk(self.apk, self.tools)
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(item["size_bytes"], self.apk.stat().st_size)
        self.assertTrue(item["file_identity_checks"]["snapshot_unchanged"])
        self.assertTrue(item["file_identity_checks"]["original_unchanged"])

    def test_nonzero_verifier_exit_cannot_be_overridden_by_positive_text(self):
        with patch.object(review, "run_tool", return_value={"exit_code": 1, "output": SIG}), self.assertRaises(review.Blocked):
            review.inspect_apk(self.apk, self.tools)

    def test_aapt_failure_overwrites_previous_success_report(self):
        report = self.root / "failed.json"; report.write_text('{"status":"passed"}')
        def outputs(tool, args):
            return {"exit_code": 1, "output": BADGING} if tool.name == "aapt" else self.fake_tool(tool, args)
        with patch.object(review, "run_tool", side_effect=outputs):
            code = review.main(["inspect", "--build-tools", str(self.tools), "--apk", str(self.apk), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertNotEqual(code, 0)
        self.assertEqual(value["status"], "blocked")
        self.assertIn("apk:aapt_failed", value["blocked_reasons"])

    def test_snapshot_mutation_during_signature_tool_is_rejected(self):
        def mutate(tool, args):
            snapshot = Path(args[-1]); snapshot.chmod(0o600); snapshot.write_bytes(b"synthetic changed snapshot")
            return self.fake_tool(tool, args)
        with patch.object(review, "run_tool", side_effect=mutate), self.assertRaisesRegex(review.Blocked, "snapshot_changed"):
            review.inspect_apk(self.apk, self.tools)

    def test_original_mutation_during_tool_execution_is_rejected(self):
        def mutate(tool, args):
            self.apk.write_bytes(b"synthetic changed original")
            return self.fake_tool(tool, args)
        with patch.object(review, "run_tool", side_effect=mutate), self.assertRaisesRegex(review.Blocked, "original_changed"):
            review.inspect_apk(self.apk, self.tools)

    def test_inspect_report_never_assesses_upgrade_or_runtime(self):
        report = self.root / "inspect.json"
        with patch.object(review, "run_tool", side_effect=self.fake_tool):
            code = review.main(["inspect", "--build-tools", str(self.tools), "--apk", str(self.apk), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(value["upgrade_decision"], "not_assessed")
        for field in ("runtime", "device", "upgrade_runtime", "source_provenance"):
            self.assertEqual(value["scope"][field], "not_tested")

    def test_compare_reinspects_both_apks_and_replaces_previous_success(self):
        candidate = self.root / "candidate.apk"; candidate.write_bytes(b"synthetic candidate")
        report = self.root / "compare.json"; report.write_text('{"status":"passed"}')
        def outputs(tool, args):
            sig = SIG.replace("A" * 64, "B" * 64) if Path(args[-1]).read_bytes() == b"synthetic candidate" else SIG
            return {"exit_code": 0, "output": sig if tool.name == "apksigner" else BADGING}
        with patch.object(review, "run_tool", side_effect=outputs) as runner:
            code = review.main(["compare", "--build-tools", str(self.tools), "--baseline", str(self.apk), "--candidate", str(candidate), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertNotEqual(code, 0)
        self.assertEqual(runner.call_count, 4)
        self.assertEqual(set(value["blocked_reasons"]), {"signer_mismatch", "version_not_advanced"})
        self.assertEqual(value["upgrade_decision"], "blocked")

    def test_compare_checks_baseline_again_after_candidate_inspection(self):
        candidate = self.root / "candidate.apk"; candidate.write_bytes(b"synthetic candidate")
        report = self.root / "changed.json"
        def outputs(tool, args):
            is_candidate = Path(args[-1]).read_bytes() == b"synthetic candidate"
            if is_candidate:
                self.apk.write_bytes(b"synthetic baseline changed after its inspection")
            badge = BADGING.replace("versionCode='5'", "versionCode='6'") if is_candidate else BADGING
            return {"exit_code": 0, "output": SIG if tool.name == "apksigner" else badge}
        with patch.object(review, "run_tool", side_effect=outputs) as runner:
            code = review.main(["compare", "--build-tools", str(self.tools), "--baseline", str(self.apk), "--candidate", str(candidate), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertNotEqual(code, 0); self.assertEqual(runner.call_count, 4)
        self.assertEqual(value["upgrade_decision"], "blocked")
        self.assertIn("baseline:original_changed_after_inspection", value["blocked_reasons"])

    def test_compare_eligible_metadata_retains_unverified_device_scope(self):
        candidate = self.root / "candidate.apk"; candidate.write_bytes(b"synthetic candidate")
        report = self.root / "eligible.json"
        def outputs(tool, args):
            badge = BADGING.replace("versionCode='5'", "versionCode='6'") if Path(args[-1]).read_bytes() == b"synthetic candidate" else BADGING
            return {"exit_code": 0, "output": SIG if tool.name == "apksigner" else badge}
        with patch.object(review, "run_tool", side_effect=outputs):
            code = review.main(["compare", "--build-tools", str(self.tools), "--baseline", str(self.apk), "--candidate", str(candidate), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(value["upgrade_decision"], "eligible_for_authorized_isolated_upgrade_test")
        self.assertTrue(all(result == "not_tested" for result in value["scope"].values()))

    def test_unsafe_report_paths_never_overwrite_inputs_or_tools(self):
        original = self.apk.read_bytes(); tool_bytes = (self.tools / "aapt").read_bytes()
        alias = self.root / "alias.json"; os.link(self.apk, alias)
        tool_alias = self.root / "tool-alias.json"; os.link(self.tools / "aapt", tool_alias)
        target = self.root / "prior.json"; target.write_text('{"original":true}')
        link = self.root / "link.json"; link.symlink_to(target)
        for report in (self.apk, alias, tool_alias, link, self.tools / "report.json", self.root):
            with self.subTest(report=report), patch.object(review, "inspect_apk") as inspect:
                code = review.main(["inspect", "--build-tools", str(self.tools), "--apk", str(self.apk), "--report", str(report)])
                self.assertNotEqual(code, 0); inspect.assert_not_called()
        self.assertEqual(self.apk.read_bytes(), original)
        self.assertEqual((self.tools / "aapt").read_bytes(), tool_bytes)
        self.assertEqual(target.read_text(), '{"original":true}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
