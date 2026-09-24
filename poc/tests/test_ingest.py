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

if __name__=="__main__": unittest.main()
