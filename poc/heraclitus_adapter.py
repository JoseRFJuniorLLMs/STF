"""Read-only loopback adapter to real HeraclitusDB REST surfaces confirmed in source."""
from __future__ import annotations
import json, urllib.request, urllib.error
from urllib.parse import urlparse, quote

ALLOWED_HOSTS={"127.0.0.1","localhost","::1"}
MAX_RESPONSE_BYTES=2*1024*1024
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

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url,code,"redirect rejected by loopback safety gate",headers,fp)

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
        self._opener=urllib.request.build_opener(_NoRedirect())
    def get(self,path:str):
        url=self.base_url+path
        parsed=urlparse(url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: request escaped loopback")
        req=urllib.request.Request(url,headers={"Accept":"application/json"})
        with self._opener.open(req,timeout=self.timeout) as r:
            final=urlparse(r.geturl())
            if final.hostname not in ALLOWED_HOSTS:
                raise ValueError("Safety gate: final URL escaped loopback")
            raw=r.read(MAX_RESPONSE_BYTES+1)
            if len(raw)>MAX_RESPONSE_BYTES:
                raise ValueError("Heraclitus response exceeds safety limit")
            return json.loads(raw.decode())
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
                safe=quote(ids[0],safe="")
                for name,suffix in {"detail":"","evidence":"/evidence","why":"/why"}.items():
                    out["incident_drilldown"][name]=self._read(f"/sentinel/incidents/{safe}{suffix}")
        return out
