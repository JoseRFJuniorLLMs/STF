import pathlib,sys,unittest,threading,urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from heraclitus_adapter import extract_incident_ids,HeraclitusAdapter,STATIC_PATHS

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

    def test_snapshot_reports_unavailable_when_every_surface_fails(self):
        adapter=HeraclitusAdapter("http://127.0.0.1:7473")
        adapter._read=lambda path: {"status":"UNAVAILABLE","path":path}
        result=adapter.snapshot()
        self.assertEqual(result["status"],"UNAVAILABLE")
        self.assertFalse(result["connected"])
        self.assertEqual(result["surface_health"],{"passed":0,"total":len(STATIC_PATHS)})

    def test_snapshot_reports_degraded_when_only_some_surfaces_pass(self):
        adapter=HeraclitusAdapter("http://127.0.0.1:7473")
        adapter._read=lambda path: {"status":"PASS" if path=="/sentinel/status" else "UNAVAILABLE","data":{},"path":path}
        result=adapter.snapshot()
        self.assertEqual(result["status"],"DEGRADED")
        self.assertTrue(result["connected"])
        self.assertEqual(result["surface_health"],{"passed":1,"total":len(STATIC_PATHS)})

    def test_snapshot_reports_connected_when_all_surfaces_pass(self):
        adapter=HeraclitusAdapter("http://127.0.0.1:7473")
        adapter._read=lambda path: {"status":"PASS","data":{},"path":path}
        result=adapter.snapshot()
        self.assertEqual(result["status"],"CONNECTED")
        self.assertTrue(result["connected"])
        self.assertEqual(result["surface_health"],{"passed":len(STATIC_PATHS),"total":len(STATIC_PATHS)})

    def test_failed_incident_drilldown_degrades_complete_static_snapshot(self):
        adapter=HeraclitusAdapter("http://127.0.0.1:7473")
        def fake_read(path):
            if path=="/sentinel/incidents":
                return {"status":"PASS","data":{"incidents":[{"id":"INC-1"}]},"path":path}
            if path.startswith("/sentinel/incidents/"):
                return {"status":"UNAVAILABLE","path":path}
            return {"status":"PASS","data":{},"path":path}
        adapter._read=fake_read
        result=adapter.snapshot()
        self.assertEqual(result["status"],"DEGRADED")
        self.assertEqual(result["surface_health"],{"passed":len(STATIC_PATHS),"total":len(STATIC_PATHS)+3})


    def test_loopback_redirect_is_rejected(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location","https://example.com/")
                self.end_headers()
        server=ThreadingHTTPServer(("127.0.0.1",0),Redirect)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            adapter=HeraclitusAdapter(f"http://127.0.0.1:{server.server_address[1]}")
            with self.assertRaises(urllib.error.HTTPError):
                adapter.get("/sentinel/status")
        finally:
            server.shutdown();server.server_close()


if __name__=="__main__": unittest.main()
