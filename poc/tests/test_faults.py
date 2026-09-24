import pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from faults import simulate,KINDS

class FaultTests(unittest.TestCase):
    def test_all_faults_resolve_without_false_success(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                r=simulate(kind)
                self.assertEqual(r["status"],"PASS")
                self.assertNotEqual(r.get("initial_state"),"SUCCESS")
    def test_policy_store_down_fails_closed(self):
        r=simulate("policy_store_down")
        self.assertEqual(r["decision"],"DENY");self.assertEqual(r["upstream_delta"],0)
    def test_post_effect_timeout_is_unknown_then_reconciled(self):
        r=simulate("timeout_after_effect")
        self.assertEqual(r["decision"],"UNKNOWN")
        self.assertEqual(r["upstream_delta"],1)
        self.assertEqual(r["final_state"],"RESOLVED_EXECUTED")
    def test_unknown_fault_is_rejected(self):
        self.assertEqual(simulate("warp_drive")["status"],"REJECT")

if __name__=="__main__": unittest.main()
