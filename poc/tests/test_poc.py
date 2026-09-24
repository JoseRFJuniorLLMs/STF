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


    def test_source_health_activates_as_events_arrive(self):
        self.assertTrue(all(x["status"]=="WAITING" for x in self.e.source_health()))
        for _ in range(7): self.e.step()
        active={x["source"] for x in self.e.source_health() if x["status"]=="ACTIVE"}
        self.assertTrue({"Firewall/WAF","IAM","Host","Network","DB Audit","Application"}.issubset(active))

    def test_why_incident_returns_evidence_chain(self):
        for _ in range(7): self.e.step()
        why=self.e.why_incident()
        self.assertEqual(why["status"],"OPEN")
        self.assertGreaterEqual(len(why["reasons"]),5)
        self.assertEqual(why["principal"],mod.COMPROMISED_PRINCIPAL)
        self.assertTrue(all("evidence_hash" in x for x in why["reasons"]))

    def test_as_of_reconstructs_pre_and_post_incident_state(self):
        self.e.run_all()
        before=self.e.as_of(3)
        after=self.e.as_of(8)
        self.assertIsNone(before["incident"])
        self.assertIsNotNone(after["incident"])
        self.assertEqual(before["upstream_hits"],0)
        self.assertEqual(after["upstream_hits"],0)
        executed=self.e.as_of(11)
        self.assertEqual(executed["upstream_hits"],1)
        self.assertEqual(executed["approval_state"],"CONSUMED")

    def test_evidence_object_exposes_chain_link(self):
        self.e.run_all()
        obj=self.e.evidence_object(5)
        self.assertEqual(obj["status"],"PASS")
        self.assertTrue(obj["provenance"]["chain_link_valid"])
        self.assertEqual(obj["provenance"]["previous_lsn"],4)
        self.assertEqual(obj["provenance"]["next_lsn"],6)

    def test_all_tamper_variants_are_detected(self):
        self.e.run_all()
        for kind in ("modify","delete","reorder","truncate"):
            with self.subTest(kind=kind):
                result=self.e.tamper_variant(kind)
                self.assertEqual(result["status"],"DETECTED")
                self.assertEqual(result["verification"]["overall"],"FAIL")

    def test_incident_report_is_explainable(self):
        self.e.run_all()
        report=self.e.incident_report()
        self.assertEqual(report["incident_id"],mod.INCIDENT_ID)
        self.assertEqual(report["controls"]["policy_enforcement"],"PASS")
        self.assertEqual(report["controls"]["hitl"],"PASS")
        self.assertEqual(report["controls"]["anti_replay"],"PASS")
        self.assertGreaterEqual(len(report["why"]["reasons"]),5)

if __name__=="__main__": unittest.main()
