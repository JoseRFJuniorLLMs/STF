"""Read-only loopback adapter to real HeraclitusDB REST surfaces confirmed in source."""
from __future__ import annotations
import json, urllib.request
from urllib.parse import urlparse, quote

ALLOWED_HOSTS={"127.0.0.1","localhost","::1"}
STATIC_PATHS={
    "sentinel_status":"/sentinel/status",
    "sentinel_incidents":"/sentinel/incidents",
    "sentinel_actions":"/sentinel/actions",
    "sentinel_dashboard":"/sentinel/dashboard",
    "telemetry_health":"/telemetry/health",
    "compliance_status":"/compliance/status",
    "agent_status":"/api/v1/agent/status",
    "red_team":"/api/v1/agent/red-team/events?limit=50",
}

def extract_incident_ids(value):
    if isinstance(value,list):
        rows=value
    elif isinstance(value,dict):
        rows=[]
        for key in ("incidents","items","data"):
            if isinstance(value.get(key),list):
                rows=value[key]; break
        if not rows and any(k in value for k in ("incident_id","id")):
            rows=[value]
    else:
        rows=[]
    out=[]
    for row in rows:
        if not isinstance(row,dict): continue
        ident=row.get("incident_id") or row.get("id")
        if ident is not None and str(ident) not in out: out.append(str(ident))
    return out

class HeraclitusAdapter:
    def __init__(self,base_url:str,timeout:float=1.5):
        self.base_url=base_url.rstrip('/'); self.timeout=timeout
        p=urlparse(self.base_url)
        if p.scheme not in {"http","https"} or p.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: Heraclitus adapter accepts only loopback URLs")
    def get(self,path:str):
        with urllib.request.urlopen(self.base_url+path,timeout=self.timeout) as r:
            return json.loads(r.read().decode())
    def _read(self,path):
        try: return {"status":"PASS","data":self.get(path),"path":path}
        except Exception as e: return {"status":"UNAVAILABLE","error":str(e),"path":path}
    def snapshot(self):
        out={"connected":True,"base_url":self.base_url,"surfaces":{},"incident_drilldown":{}}
        for key,path in STATIC_PATHS.items():
            out["surfaces"][key]=self._read(path)
        incidents=out["surfaces"].get("sentinel_incidents",{})
        if incidents.get("status")=="PASS":
            ids=extract_incident_ids(incidents.get("data"))
            out["incident_ids"]=ids
            if ids:
                incident_id=ids[0]
                safe=quote(incident_id,safe="")
                for name,suffix in {"detail":"","evidence":"/evidence","why":"/why"}.items():
                    out["incident_drilldown"][name]=self._read(f"/sentinel/incidents/{safe}{suffix}")
        return out
