import pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from heraclitus_adapter import extract_incident_ids,HeraclitusAdapter

class AdapterTests(unittest.TestCase):
    def test_extract_incident_ids_from_common_shapes(self):
        self.assertEqual(extract_incident_ids([{"incident_id":"A"},{"id":"B"}]),["A","B"])
        self.assertEqual(extract_incident_ids({"incidents":[{"incident_id":"C"}]}),["C"])
        self.assertEqual(extract_incident_ids({"items":[{"id":"D"}]}),["D"])
    def test_duplicate_incident_ids_are_deduplicated(self):
        self.assertEqual(extract_incident_ids([{"id":"A"},{"incident_id":"A"}]),["A"])
    def test_remote_host_is_rejected(self):
        with self.assertRaises(ValueError): HeraclitusAdapter("https://example.com")
    def test_loopback_is_accepted(self):
        HeraclitusAdapter("http://127.0.0.1:7473")

if __name__=="__main__": unittest.main()
