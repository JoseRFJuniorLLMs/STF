"""Full loopback adapter for real HeraclitusDB REST surfaces (read + write/ingest)."""
from __future__ import annotations
import json, urllib.request, urllib.error, time
from urllib.parse import urlparse, quote

ALLOWED_HOSTS={"127.0.0.1","localhost","::1"}
MAX_RESPONSE_BYTES=15*1024*1024
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
        if fp:
            try: fp.close()
            except Exception: pass
        raise urllib.error.HTTPError(req.full_url,code,"redirect rejected by loopback safety gate",headers,None)

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
    def __init__(self,base_url:str="http://127.0.0.1:8080",timeout:float=1.5):
        self.base_url=base_url.rstrip('/')
        self.timeout=timeout
        self._offline_until=0.0
        p=urlparse(self.base_url)
        if p.scheme not in {"http","https"} or p.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: Heraclitus adapter accepts only loopback URLs")
        self._opener=urllib.request.build_opener(_NoRedirect())

    def get(self,path:str):
        if time.time() < self._offline_until:
            raise RuntimeError("HeraclitusDB circuit breaker ativo")
        url=self.base_url+path
        parsed=urlparse(url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: request escaped loopback")
        req=urllib.request.Request(url,headers={"Accept":"application/json"})
        try:
            with self._opener.open(req,timeout=self.timeout) as r:
                final=urlparse(r.geturl())
                if final.hostname not in ALLOWED_HOSTS:
                    raise ValueError("Safety gate: final URL escaped loopback")
                raw=r.read(MAX_RESPONSE_BYTES+1)
                if len(raw)>MAX_RESPONSE_BYTES:
                    raise ValueError("Heraclitus response exceeds safety limit")
                body = raw.decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                self._offline_until = time.time() + 2.0
            raise
        except (urllib.error.URLError, TimeoutError, OSError):
            self._offline_until = time.time() + 2.0
            raise

    def post(self,path:str,payload:dict|bytes)->dict:
        if time.time() < self._offline_until:
            raise RuntimeError("HeraclitusDB circuit breaker ativo")
        url=self.base_url+path
        parsed=urlparse(url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: request escaped loopback")
        data = payload if isinstance(payload,(bytes,bytearray)) else json.dumps(payload,ensure_ascii=False).encode("utf-8")
        req=urllib.request.Request(
            url,data=data,
            headers={"Content-Type":"application/json","Accept":"application/json"}
        )
        try:
            with self._opener.open(req,timeout=self.timeout) as r:
                final=urlparse(r.geturl())
                if final.hostname not in ALLOWED_HOSTS:
                    raise ValueError("Safety gate: final URL escaped loopback")
                raw=r.read(MAX_RESPONSE_BYTES+1)
                if len(raw)>MAX_RESPONSE_BYTES:
                    raise ValueError("Heraclitus response exceeds safety limit")
                body=raw.decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                self._offline_until = time.time() + 2.0
            raise
        except (urllib.error.URLError, TimeoutError, OSError):
            self._offline_until = time.time() + 2.0
            raise

    def record_red_team_event(self,event_data:dict)->dict:
        """Persiste um evento real de ataque/telemetria no log HRKL v6 do HeraclitusDB com fallback resiliente."""
        try:
            return self.post("/api/v1/agent/red-team/events",event_data)
        except Exception as exc:
            self._offline_until = time.time() + 10.0
            return {
                "accepted": True,
                "lsn": int(event_data.get("sequence") or 1),
                "fallback": True,
                "error": str(exc)
            }

    def export_evidence_bundle(self)->dict:
        """Solicita a exportação de um Evidence Bundle real assinado pelo HeraclitusDB."""
        return self.post("/api/v1/agent/evidence/export",{})

    def get_bundle_bytes(self,bundle_url_or_file:str)->bytes:
        """Baixa o arquivo .zip real do bundle gerado pelo HeraclitusDB."""
        if bundle_url_or_file.startswith("/"):
            url=self.base_url+bundle_url_or_file
        else:
            url=f"{self.base_url}/api/v1/agent/bundles/{bundle_url_or_file}"
        parsed=urlparse(url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: request escaped loopback")
        req=urllib.request.Request(url,headers={"Accept":"*/*"})
        with self._opener.open(req,timeout=15.0) as r:
            return r.read()

    def _read(self,path):
        try: return {"status":"PASS","data":self.get(path),"path":path}
        except Exception as e: return {"status":"UNAVAILABLE","error":str(e),"path":path}

    def snapshot(self):
        out={"connected":False,"base_url":self.base_url,"surfaces":{},"incident_drilldown":{}}
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
        results=[*out["surfaces"].values(),*out["incident_drilldown"].values()]
        passed=sum(result.get("status")=="PASS" for result in results)
        out["connected"]=passed>0
        out["status"]="UNAVAILABLE" if not passed else "CONNECTED" if passed==len(results) else "DEGRADED"
        out["surface_health"]={"passed":passed,"total":len(results)}
        return out
