import importlib.util
import json
import pathlib
import unittest
import sys

HERE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stf_poc_server", HERE / "server.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class PocEngineTests(unittest.TestCase):
    def setUp(self): self.e = mod.PocEngine()
    def test_phase1_opens_incident(self):
        for _ in range(7): self.e.step()
        self.assertIsNotNone(self.e.incident); self.assertEqual(self.e.incident["state"], "OPEN")
        self.assertGreaterEqual(len(self.e.signals), 5); self.assertEqual(self.e.incident["principal"], mod.COMPROMISED_PRINCIPAL)
    def test_denied_write_has_zero_upstream_delta(self):
        for _ in range(8): self.e.step()
        ev=self.e.events[-1]; self.assertEqual(ev.event_type,"app.case_update_requested"); self.assertEqual(ev.outcome,"DENY")
        self.assertEqual(ev.upstream_delta,0); self.assertEqual(self.e.upstream_hits,0)
    def test_human_approval_executes_once_and_replay_denied(self):
        for _ in range(12): self.e.step()
        self.assertEqual(self.e.upstream_hits,1); replay=self.e.events[-1]
        self.assertEqual(replay.event_type,"approval.replay"); self.assertEqual(replay.outcome,"DENY"); self.assertEqual(replay.upstream_delta,0)
        self.assertIn("APR-001",self.e.approvals_consumed)
    def test_identity_and_parameter_binding(self):
        for _ in range(14): self.e.step()
        identity=self.e.events[-2]; params=self.e.events[-1]
        self.assertEqual(identity.reason_code,"IDENTITY_BINDING_MISMATCH"); self.assertEqual(params.reason_code,"PARAMETERS_DIGEST_MISMATCH")
        self.assertEqual(identity.upstream_delta,0); self.assertEqual(params.upstream_delta,0)
    def test_evidence_bundle_verifies_and_tamper_fails(self):
        self.e.run_all(); bundle=self.e.evidence_bundle()
        self.assertEqual(self.e.verify_bundle(bundle)["overall"],"PASS")
        tampered=json.loads(json.dumps(bundle)); tampered["events"][0]["summary"]="ADULTERADO"
        self.assertEqual(self.e.verify_bundle(tampered)["overall"],"FAIL")
    def test_full_qualification(self):
        self.e.run_all(); self.assertEqual([x for x in self.e.qualification() if not x["ok"]],[])
        self.assertEqual(self.e.tamper_status,"DETECTED"); self.assertEqual(self.e.offline_verify,"PASS")
    def test_hash_chain_is_deterministic(self):
        a=mod.PocEngine();a.run_all();b=mod.PocEngine();b.run_all()
        self.assertEqual([e.event_hash for e in a.events],[e.event_hash for e in b.events])
        self.assertEqual(a.evidence_bundle()["merkle_root"],b.evidence_bundle()["merkle_root"])
    def test_loopback_adapter_rejects_remote(self):
        sys.path.insert(0,str(HERE)); from heraclitus_adapter import HeraclitusAdapter
        with self.assertRaises(ValueError): HeraclitusAdapter("https://example.com")
    def test_offline_verifier_module(self):
        self.e.run_all(); sys.path.insert(0,str(HERE)); import verify
        self.assertEqual(verify.verify(self.e.evidence_bundle())["overall"],"PASS")

if __name__=="__main__": unittest.main()
