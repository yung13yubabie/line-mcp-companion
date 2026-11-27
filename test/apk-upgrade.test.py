#!/usr/bin/env python3
"""Synthetic metadata/pin/race regression tests; no signing, installation or device pass."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("apk_upgrade", ROOT / "scripts/apk-upgrade.py")
upgrade = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(upgrade)
SIG = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Number of signers: 1
Signer #1 certificate SHA-256 digest: {cert}
"""
BAD = """package: name='{package}' versionCode='{code}' versionName='{version}'
sdkVersion:'29'
targetSdkVersion:'35'
native-code: '{abi}'
"""

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name); self.tools = self.home/'tools'; self.tools.mkdir()
        for n in ['aapt','apksigner']:
            p=self.tools/n; p.write_text('synthetic never-executed tool'); p.chmod(0o755)
        self.base=self.home/'base.apk'; self.base.write_bytes(b'synthetic baseline, not actual APK')
        self.candidate=self.home/'candidate.apk'; self.candidate.write_bytes(b'synthetic candidate, not actual APK')
        self.report=self.home/'result.json'; self.calls=0
        self.kind='release'; self.cert='a'*64; self.candidate_cert=self.cert
        self.candidate_code=6; self.candidate_abi='x86_64'
    def args(self, command='compare', kind=None):
        argv=[command,'--package-kind',kind or self.kind,'--build-tools',str(self.tools),'--expected-signer-sha256',self.cert,'--report',str(self.report)]
        files=[('apk',self.candidate)] if command=='inspect' else [('baseline',self.base),('candidate',self.candidate)]
        for field,p in files: argv+=['--'+field,str(p),'--'+field+'-sha256',hashlib.sha256(p.read_bytes()).hexdigest()]
        return argv
    def fake_tool(self, tool, args):
        self.calls+=1; candidate=self.calls>2 if self.command=='compare' else True
        cert=self.candidate_cert if candidate else self.cert
        if tool.name=='apksigner': return {'exit_code':0,'output':SIG.format(cert=cert)}
        kind=self.kind; version='0.3.1-review' if kind=='review' else '0.3.1'
        return {'exit_code':0,'output':BAD.format(package='tw.linemcp.app'+('.review' if kind=='review' else ''),code=self.candidate_code if candidate else 5,version=version,abi=self.candidate_abi if candidate else 'x86_64')}
    def run_cli(self, argv=None, command='compare', runner=None):
        self.command=command
        with patch.object(upgrade.review,'run_tool',runner or self.fake_tool), contextlib.redirect_stdout(io.StringIO()):
            code=upgrade.main(argv or self.args(command))
        return code,json.loads(self.report.read_text()) if self.report.exists() else None
    def test_release_profile_is_explicit_and_old_review_default_is_unchanged(self):
        sig=SIG.format(cert=self.cert); bad=BAD.format(package='tw.linemcp.app',code=5,version='0.3.1',abi='x86_64')
        with self.assertRaises(upgrade.review.Blocked): upgrade.review.parse_inspection(sig,bad)
        self.assertEqual(upgrade.review.parse_inspection(sig,bad,package_kind='release')['package'],'tw.linemcp.app')
        for package,version,kind in [('tw.linemcp.app.review','0.3.1-review','release'),('tw.linemcp.app','0.3.1-review','release'),('tw.other.app','0.3.1','release'),('tw.linemcp.app','0.3.1','unknown')]:
            with self.subTest(package=package,version=version,kind=kind),self.assertRaises(upgrade.review.Blocked):
                upgrade.review.parse_inspection(sig,BAD.format(package=package,code=5,version=version,abi='x86_64'),package_kind=kind)
    def test_synthetic_release_eligible_is_only_metadata_not_install_or_publisher(self):
        code,r=self.run_cli(); self.assertEqual(code,0); self.assertEqual(r['upgrade_decision'],'eligible_for_authorized_isolated_upgrade_test')
        self.assertTrue(all(v=='not_tested' for v in r['scope'].values()))
        self.assertEqual(r['expected_apk_sha256']['candidate'],r['candidate']['sha256']); self.assertEqual(self.calls,4)
    def test_review_profile_cannot_be_relabeled_as_formal_release(self):
        self.kind='review'; code,r=self.run_cli(self.args(kind='release'))
        self.assertEqual(code,1); self.assertTrue(all('release_package_and_version_required' in x for x in r['blocked_reasons']))
    def test_inspect_is_pinned_but_never_upgrade_assessment(self):
        code,r=self.run_cli(command='inspect'); self.assertEqual(code,0); self.assertEqual(r['upgrade_decision'],'not_assessed')
    def test_hash_mismatch_blocks_before_tools_and_replaces_stale_success(self):
        self.report.write_text('{"status":"metadata_conditions_satisfied"}')
        argv=self.args(command='inspect'); argv[-1]='b'*64
        code,r=self.run_cli(argv,command='inspect'); self.assertEqual(code,1); self.assertEqual(self.calls,0)
        self.assertEqual(r['blocked_reasons'],['apk:apk_sha256_mismatch']); self.assertEqual(r['status'],'blocked')
    def test_signer_mismatch_and_same_code_aggregate_without_upgrade(self):
        self.candidate_cert='b'*64; self.candidate_code=5
        code,r=self.run_cli(); self.assertEqual(code,1)
        self.assertEqual(set(r['blocked_reasons']),{'candidate:expected_signer_mismatch','signer_mismatch','version_not_advanced'})
    def test_same_signer_downgrade_is_blocked(self):
        self.candidate_code=4; code,r=self.run_cli(); self.assertEqual(code,1); self.assertIn('version_not_advanced',r['blocked_reasons'])
    def test_single_abi_must_match(self):
        self.candidate_abi='arm64-v8a'; code,r=self.run_cli(); self.assertEqual(code,1); self.assertIn('abi_mismatch',r['blocked_reasons'])
    def test_changed_baseline_after_candidate_inspection_is_blocked(self):
        def runner(tool,args):
            result=self.fake_tool(tool,args)
            if self.calls==4:self.base.write_bytes(b'changed own synthetic baseline')
            return result
        code,r=self.run_cli(runner=runner); self.assertEqual(code,1); self.assertIn('baseline:original_changed_after_inspection',r['blocked_reasons'])
    def test_wrong_publisher_pin_does_not_accept_two_self_consistent_files(self):
        argv=self.args(); argv[argv.index('--expected-signer-sha256')+1]='c'*64
        code,r=self.run_cli(argv); self.assertEqual(code,1)
        self.assertEqual(set(r['blocked_reasons']),{'baseline:expected_signer_mismatch','candidate:expected_signer_mismatch'})
    def test_report_cannot_overwrite_apk_or_build_tool(self):
        for target in [self.base,self.tools/'aapt']:
            content=target.read_bytes(); self.report=target
            argv=self.args()
            with patch.object(upgrade.review,'run_tool') as run, contextlib.redirect_stdout(io.StringIO()):code=upgrade.main(argv)
            self.assertEqual(code,1); run.assert_not_called(); self.assertEqual(target.read_bytes(),content)
    def test_timeout_is_blocked_with_fresh_report(self):
        import subprocess
        def runner(tool,args):raise subprocess.TimeoutExpired(str(tool),30)
        code,r=self.run_cli(runner=runner); self.assertEqual(code,1); self.assertEqual(r['status'],'blocked')
        self.assertTrue(r['blocked_reasons']); self.assertEqual(r['upgrade_decision'],'blocked')

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(UpgradeTests))
    print(f'Executed {result.testsRun}; skipped {len(result.skipped)}; failures {len(result.failures)}; errors {len(result.errors)}')
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped) or result.testsRun==0)
