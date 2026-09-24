import pathlib,sys,unittest
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from correlation import correlate

def sig(i,source,entities,severity="HIGH"):
    return {"signal_id":f"S{i}","lsn":i,"source_class":source,"source":source,"entities":entities,"severity":severity}

class CorrelationTests(unittest.TestCase):
    def test_chain_correlates_without_campaign_id(self):
        signals=[
            sig(1,"EDGE",["203.0.113.42","portal"]),
            sig(2,"IDENTITY",["203.0.113.42","service-account-17"]),
            sig(3,"HOST",["service-account-17","srv-app-07"]),
            sig(4,"NETWORK",["service-account-17","srv-app-07","srv-db-02"]),
            sig(5,"DATABASE",["service-account-17","srv-db-02","db-lab"]),
        ]
        r=correlate(signals)["best"]
        self.assertTrue(r["qualifies"]); self.assertEqual(r["confidence"],"HIGH")
        self.assertEqual(len(r["signal_ids"]),5)
    def test_unrelated_signal_is_not_absorbed(self):
        signals=[
            sig(1,"EDGE",["203.0.113.42"]),
            sig(2,"IDENTITY",["203.0.113.42","service-account-17"]),
            sig(3,"HOST",["service-account-17","srv-app-07"]),
            sig(4,"NETWORK",["service-account-17","srv-db-02"]),
            sig(99,"APPLICATION",["innocent-user","case://OTHER"]),
        ]
        r=correlate(signals)
        self.assertTrue(r["best"]["qualifies"])
        self.assertNotIn("S99",r["best"]["signal_ids"])
        self.assertEqual(len(r["components"]),2)
    def test_same_time_is_not_enough(self):
        signals=[sig(1,"EDGE",["a"]),sig(2,"IDENTITY",["b"]),sig(3,"HOST",["c"]),sig(4,"NETWORK",["d"])]
        self.assertFalse(correlate(signals)["best"]["qualifies"])


    def test_related_entities_outside_temporal_window_do_not_correlate(self):
        signals=[
            {"signal_id":"S1","lsn":1,"hlc":1,"source_class":"IDENTITY","source":"IDENTITY","entities":["principal:p","ip:203.0.113.42"],"severity":"HIGH"},
            {"signal_id":"S2","lsn":2,"hlc":2,"source_class":"HOST","source":"HOST","entities":["principal:p","host:h1"],"severity":"HIGH"},
            {"signal_id":"S3","lsn":3,"hlc":100,"source_class":"NETWORK","source":"NETWORK","entities":["principal:p","host:h1","host:h2"],"severity":"HIGH"},
            {"signal_id":"S4","lsn":4,"hlc":101,"source_class":"DATABASE","source":"DATABASE","entities":["principal:p","db:d1"],"severity":"HIGH"},
        ]
        self.assertFalse(correlate(signals,max_hlc_span=20)["best"]["qualifies"])

    def test_typed_entities_prevent_generic_asset_cross_link(self):
        signals=[
            {"signal_id":"A1","lsn":1,"hlc":1,"source_class":"IDENTITY","source":"IDENTITY","entities":["principal:a","service:shared"],"severity":"HIGH"},
            {"signal_id":"A2","lsn":2,"hlc":2,"source_class":"HOST","source":"HOST","entities":["principal:a","host:a1"],"severity":"HIGH"},
            {"signal_id":"B1","lsn":3,"hlc":3,"source_class":"IDENTITY","source":"IDENTITY","entities":["principal:b","service:shared"],"severity":"HIGH"},
            {"signal_id":"B2","lsn":4,"hlc":4,"source_class":"HOST","source":"HOST","entities":["principal:b","host:b1"],"severity":"HIGH"},
        ]
        r=correlate(signals)
        self.assertGreaterEqual(len(r["components"]),2)

if __name__=="__main__": unittest.main()
