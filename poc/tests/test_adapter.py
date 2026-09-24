import pathlib,sys,unittest,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
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
            with self.assertRaises(Exception):
                adapter.get("/sentinel/status")
        finally:
            server.shutdown();server.server_close()


if __name__=="__main__": unittest.main()
