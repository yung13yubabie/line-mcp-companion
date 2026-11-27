"""Independent offline policy tests. Synthetic lifecycle labels are not real runtimes."""
import copy, importlib.util, json, os, tempfile, unittest
from datetime import date
from pathlib import Path
ROOT=Path(os.environ.get('RUNTIME_REVIEW_ROOT',str(Path(__file__).resolve().parents[2])))
spec=importlib.util.spec_from_file_location('independent_native_runtime',ROOT/'scripts/node-android/native-runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
BASE=json.loads((ROOT/'android/native-runtime.lock.json').read_text())
def candidate():
    lock=copy.deepcopy(BASE);lock['production_ready']=True;lock['production_blockers']=[]
    for entry in lock['packages']:
        if entry['Package']=='openssl':entry['Version']='1:3.5.10'
    return lock
class IndependentPolicyTests(unittest.TestCase):
    def test_real_eol_runtime_cannot_be_approved_by_flags(self):
        lock=copy.deepcopy(BASE);lock['production_ready']=True;lock['production_blockers']=[]
        with self.assertRaisesRegex(RuntimeError,'OPENSSL_36_EOL'):runtime.verify_policy(lock,True)
    def test_utc_date_lifecycle_boundary_and_review_expiry(self):
        lock=candidate();lock['snapshot_date']='2026-11-26T00:15:00+00:00'
        runtime.verify_policy(lock,True,date(2026,12,26))
        with self.assertRaisesRegex(RuntimeError,'STALE'):runtime.verify_policy(lock,True,date(2026,12,27))
        # Offset 01:00 means prior UTC date, hence 31 days old on the otherwise allowed edge.
        lock['snapshot_date']='2026-11-26T00:15:00+01:00'
        with self.assertRaisesRegex(RuntimeError,'SNAPSHOT_STALE'):runtime.verify_policy(lock,True,date(2026,12,26))
    def test_dual_abi_node_selection_and_nonstable_openssl_fail_closed(self):
        lock=candidate();lock['packages'].append(copy.deepcopy(next(x for x in lock['packages'] if x['Package']=='nodejs-lts')))
        with self.assertRaisesRegex(RuntimeError,'ABI'):runtime.verify_policy(lock,True,date(2026,12,2))
        lock=candidate()
        for entry in lock['packages']:
            if entry['Package']=='openssl':entry['Version']='1:3.5.10~pre1'
        with self.assertRaisesRegex(RuntimeError,'stable reviewed format'):runtime.verify_policy(lock,True,date(2026,12,2))
    def test_exact_snapshot_second_boundary_and_same_day_future_are_enforced(self):
        lock=candidate();lock['snapshot_date']='2026-11-02T00:00:00Z'
        runtime.verify_policy(lock,True,date(2026,12,2))
        for timestamp in ['2026-11-01T23:59:59Z','2026-12-02T00:00:01Z']:
            lock['snapshot_date']=timestamp
            with self.assertRaisesRegex(RuntimeError,'SNAPSHOT_STALE'):runtime.verify_policy(lock,True,date(2026,12,2))
    def test_cross_abi_debian_revision_disagreement_is_rejected(self):
        lock=candidate()
        next(x for x in lock['packages'] if x['Package']=='openssl')['Version']='1:3.5.10-1'
        with self.assertRaisesRegex(RuntimeError,'versions must match'):runtime.verify_policy(lock,True,date(2026,12,2))
    def test_synthetic_supported_label_does_not_authenticate_real_signed_packages(self):
        lock=candidate();runtime.verify_policy(lock,True,date(2026,12,2))
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaisesRegex(RuntimeError,'selection does not match signed metadata'):
                runtime.verify_provenance(lock,Path(work))
    def test_timezone_equivalent_signed_timestamp_is_accepted_but_relabel_is_not(self):
        lock=copy.deepcopy(BASE);lock['snapshot_date']='2026-11-25T15:12:38+08:00'
        with tempfile.TemporaryDirectory() as work:
            runtime.verify_provenance(lock,Path(work))
            lock['snapshot_date']='2026-11-25T15:12:39+08:00'
            with self.assertRaisesRegex(RuntimeError,'does not match signed metadata'):
                runtime.verify_provenance(lock,Path(work))
if __name__=='__main__':unittest.main(verbosity=2)
