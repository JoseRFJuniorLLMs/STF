import pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
import telemetry
from detector import evaluate,rules_catalog

class DetectorTests(unittest.TestCase):
    def test_sample_campaign_triggers_six_explainable_rules(self):
        detections=[]
        for kind,raw in telemetry.sample_campaign():
            d=evaluate(telemetry.normalize(kind,raw))
            self.assertIsNotNone(d)
            detections.append(d)
        self.assertEqual(len({d.rule_id for d in detections}),6)
        self.assertEqual(len(rules_catalog()),6)
    def test_benign_edge_does_not_trigger(self):
        raw={"event_id":"B1","src_ip":"198.51.100.10","dst_service":"portal-synthetic","action":"ALLOW","waf_score":12}
        self.assertIsNone(evaluate(telemetry.normalize("firewall",raw)))
    def test_trusted_identity_does_not_trigger(self):
        raw={"event_id":"B2","principal":"service-ok","context":"known-device","result":"ALLOW","device_trust":"trusted"}
        self.assertIsNone(evaluate(telemetry.normalize("identity",raw)))
    def test_detection_contains_entities_and_explanation(self):
        kind,raw=telemetry.sample_campaign()[1]
        d=evaluate(telemetry.normalize(kind,raw))
        self.assertIn("principal:service-account-17",d.entities)
        self.assertTrue(d.explanation)
        self.assertTrue(d.rule_id.startswith("DET-"))

if __name__=="__main__": unittest.main()
