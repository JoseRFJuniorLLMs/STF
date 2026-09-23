"""Read-only loopback adapter to selected real HeraclitusDB REST surfaces."""
from __future__ import annotations
import json, urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS={"127.0.0.1","localhost","::1"}
PATHS={
    "sentinel_status":"/sentinel/status",
    "agent_status":"/api/v1/agent/status",
    "red_team":"/api/v1/agent/red-team/events?limit=50",
}

class HeraclitusAdapter:
    def __init__(self,base_url:str,timeout:float=1.5):
        self.base_url=base_url.rstrip('/'); self.timeout=timeout
        p=urlparse(self.base_url)
        if p.scheme not in {"http","https"} or p.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: Heraclitus adapter accepts only loopback URLs")
    def get(self,path:str):
        with urllib.request.urlopen(self.base_url+path,timeout=self.timeout) as r:
            return json.loads(r.read().decode())
    def snapshot(self):
        out={"connected":True,"base_url":self.base_url,"surfaces":{}}
        for key,path in PATHS.items():
            try: out["surfaces"][key]={"status":"PASS","data":self.get(path)}
            except Exception as e: out["surfaces"][key]={"status":"UNAVAILABLE","error":str(e)}
        return out
