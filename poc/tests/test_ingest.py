import importlib.util,pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location("stf_poc_ingest_server",HERE/"server.py")
mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
import telemetry

class IngestTests(unittest.TestCase):
    def test_raw_telemetry_pipeline_opens_incident_without_scripted_steps(self):
        e=mod.PocEngine()
        for kind,raw in telemetry.sample_campaign():
            result=e.ingest_telemetry(kind,raw)
            self.assertIn("ingested",result)
        self.assertEqual(len(e.signals),6)
        self.assertIsNotNone(e.incident)
        self.assertTrue(e.incident["correlation"]["qualifies"])
        self.assertGreaterEqual(len(e.incident["correlation"]["sources"]),4)
    def test_benign_raw_event_does_not_create_signal(self):
        e=mod.PocEngine()
        raw={"event_id":"BENIGN-1","src_ip":"198.51.100.10","dst_service":"portal-synthetic","action":"ALLOW","waf_score":10}
        r=e.ingest_telemetry("firewall",raw)
        self.assertIsNone(r["detection"])
        self.assertEqual(len(e.signals),0)
        self.assertIsNone(e.incident)
    def test_invalid_kind_is_rejected(self):
        e=mod.PocEngine()
        with self.assertRaises(ValueError): e.ingest_telemetry("telepathy",{"event_id":"X"})


    def test_external_pipeline_phase1_to_phase2_hitl_and_replay(self):
        e=mod.PocEngine()
        for kind,raw in telemetry.sample_campaign():
            e.ingest_telemetry(kind,raw)
        self.assertIsNotNone(e.incident)

        denied=e.submit_action("case_write","service-account-17",mod.SYNTHETIC_CASE,{"field":"metadata"})
        self.assertEqual(denied["decision"]["outcome"],"DENY")
        self.assertEqual(denied["event"]["upstream_delta"],0)
        self.assertEqual(e.upstream_hits,0)

        params={"document":"DOC-001","format":"pdf"}
        requested=e.submit_action("export_restricted","service-account-17","document://SYNTHETIC/DOC-001",params)
        self.assertEqual(requested["decision"]["outcome"],"REQUIRE_HITL")
        approval_id=requested["pending_approval"]["approval_id"]

        granted=e.grant_approval(approval_id,"human:approver-api")
        self.assertEqual(granted["status"],"APPROVED")

        executed=e.submit_action("export_restricted","service-account-17","document://SYNTHETIC/DOC-001",params)
        self.assertTrue(executed["decision"]["effect_allowed"])
        self.assertEqual(executed["event"]["outcome"],"PASS")
        self.assertEqual(e.upstream_hits,1)

        replay=e.submit_action("export_restricted","service-account-17","document://SYNTHETIC/DOC-001",params)
        self.assertEqual(replay["decision"]["reason_code"],"REPLAY_DETECTED")
        self.assertEqual(replay["event"]["upstream_delta"],0)
        self.assertEqual(e.upstream_hits,1)

    def test_external_identity_and_parameter_binding(self):
        e=mod.PocEngine()
        for kind,raw in telemetry.sample_campaign(): e.ingest_telemetry(kind,raw)
        params={"document":"DOC-001","format":"pdf"}
        req=e.submit_action("export_restricted","service-account-17","document://SYNTHETIC/DOC-001",params)
        e.grant_approval(req["pending_approval"]["approval_id"],"human:approver-api")
        identity=e.submit_action("export_restricted","agent:other","document://SYNTHETIC/DOC-001",params)
        self.assertEqual(identity["decision"]["reason_code"],"IDENTITY_BINDING_MISMATCH")
        changed=e.submit_action("export_restricted","service-account-17","document://SYNTHETIC/DOC-999",{"document":"DOC-999","format":"pdf"})
        self.assertEqual(changed["decision"]["reason_code"],"PARAMETERS_DIGEST_MISMATCH")


    def test_duplicate_raw_event_is_idempotent(self):
        e=mod.PocEngine()
        kind,raw=telemetry.sample_campaign()[0]
        first=e.ingest_telemetry(kind,raw)
        second=e.ingest_telemetry(kind,raw)
        self.assertEqual(first["status"],"INGESTED")
        self.assertEqual(second["status"],"IDEMPOTENT")
        self.assertEqual(len(e.events),1)

    def test_same_raw_id_with_different_payload_is_conflict(self):
        e=mod.PocEngine()
        kind,raw=telemetry.sample_campaign()[0]
        e.ingest_telemetry(kind,raw)
        changed=dict(raw); changed["waf_score"]=99
        conflict=e.ingest_telemetry(kind,changed)
        self.assertEqual(conflict["status"],"CONFLICT")
        self.assertEqual(len(e.events),1)

    def test_malformed_telemetry_types_are_rejected(self):
        e=mod.PocEngine()
        with self.assertRaises(ValueError):
            e.ingest_telemetry("db",{"event_id":"x","principal":"p","database":"d","operation":123})


    def test_existing_incident_is_not_replaced_by_unrelated_stronger_component(self):
        e=mod.PocEngine()
        for kind,raw in telemetry.sample_campaign(): e.ingest_telemetry(kind,raw)
        original_principal=e.incident["principal"]
        unrelated=[
          ("identity",{"event_id":"B-IAM","principal":"other-principal","source_ip":"198.51.100.77","context":"new-device","result":"OBSERVED","severity":"HIGH","device_trust":"unknown"}),
          ("host",{"event_id":"B-HOST","principal":"other-principal","host":"other-app","process":"synthetic-worker","os":"Linux","severity":"HIGH"}),
          ("network",{"event_id":"B-NET","principal":"other-principal","src_host":"other-app","dst_host":"other-db","severity":"HIGH"}),
          ("db",{"event_id":"B-DB","principal":"other-principal","database":"other-db","operation":"query","rows":99,"severity":"CRITICAL"}),
        ]
        for kind,raw in unrelated: e.ingest_telemetry(kind,raw)
        self.assertEqual(e.incident["principal"],original_principal)
        self.assertIn("principal:"+original_principal,e.incident["correlation"]["entities"])

if __name__=="__main__": unittest.main()
