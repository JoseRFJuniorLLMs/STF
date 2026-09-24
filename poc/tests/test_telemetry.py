import pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
import telemetry

class TelemetryAdapterTests(unittest.TestCase):
    def test_all_sample_sources_normalize(self):
        rows=[telemetry.normalize(k,v) for k,v in telemetry.sample_campaign()]
        self.assertEqual(len(rows),6)
        self.assertEqual({r["source_class"] for r in rows},{"EDGE","IDENTITY","HOST","NETWORK","DATABASE","APPLICATION"})
        self.assertTrue(all(r["raw_id"].startswith("RAW-") for r in rows))
    def test_raw_is_preserved(self):
        kind,raw=telemetry.sample_campaign()[0]
        out=telemetry.normalize(kind,raw)
        self.assertEqual(out["raw"],raw)
        self.assertEqual(out["actor"],"203.0.113.42")
    def test_missing_required_field_rejected(self):
        with self.assertRaises(ValueError): telemetry.normalize("identity",{"event_id":"x"})
    def test_unknown_adapter_rejected(self):
        with self.assertRaises(ValueError): telemetry.normalize("magic-box",{})

if __name__=="__main__": unittest.main()
