#!/usr/bin/env python3
"""Portable loopback HTTP smoke test for STF POC."""
from __future__ import annotations
import json, pathlib, subprocess, sys, time, urllib.request

ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from telemetry import sample_campaign

PORT=18787
BASE=f"http://127.0.0.1:{PORT}"

def get(path):
    with urllib.request.urlopen(BASE+path,timeout=2) as r:
        return json.loads(r.read().decode())

def post(path,body=None):
    raw=json.dumps(body or {}).encode("utf-8")
    req=urllib.request.Request(BASE+path,data=raw,method="POST",headers={"Content-Type":"application/json","X-STF-POC":"1"})
    with urllib.request.urlopen(req,timeout=2) as r:
        return json.loads(r.read().decode())

def main():
    p=subprocess.Popen([sys.executable,str(ROOT/"server.py"),"--host","127.0.0.1","--port",str(PORT)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.time()+8
        while time.time()<deadline:
            try:
                if get("/api/health").get("status")=="ok": break
            except Exception: time.sleep(.1)
        else: raise RuntimeError("server did not become healthy")

        # Scripted route still works.
        state=get("/api/state")
        if state["step"]!=0: raise RuntimeError("fresh state step != 0")
        stepped=post("/api/step")
        if stepped["step"]!=1 or len(stepped["events"])!=1: raise RuntimeError("step endpoint failed")
        if get("/api/evidence").get("event_count")!=1: raise RuntimeError("evidence endpoint failed")

        # Reset and exercise the exact external API path used by API Lab.
        post("/api/reset")
        for kind,raw in sample_campaign():
            ingested=post("/api/telemetry?kind="+kind,raw)
            if "ingested" not in ingested: raise RuntimeError("telemetry endpoint failed")
        state=get("/api/state")
        if not state.get("incident"): raise RuntimeError("external telemetry did not open incident")
        if len(state.get("signals",[]))!=6: raise RuntimeError("expected six security signals")

        write=post("/api/action",{
            "action":"case_write","principal":"service-account-17",
            "target":"case://SYNTHETIC/RE-000001","parameters":{"field":"metadata"},
        })
        if write["decision"]["outcome"]!="DENY" or write["event"]["upstream_delta"]!=0:
            raise RuntimeError("case write did not fail closed")

        params={"document":"DOC-001","format":"pdf"}
        request=post("/api/action",{
            "action":"export_restricted","principal":"service-account-17",
            "target":"document://SYNTHETIC/DOC-001","parameters":params,
        })
        if request["decision"]["outcome"]!="REQUIRE_HITL": raise RuntimeError("export did not require HITL")
        approval_id=request["pending_approval"]["approval_id"]

        granted=post("/api/approval/grant",{"approval_id":approval_id,"approver":"human:smoke"})
        if granted["status"]!="APPROVED": raise RuntimeError("approval grant failed")

        executed=post("/api/action",{
            "action":"export_restricted","principal":"service-account-17",
            "target":"document://SYNTHETIC/DOC-001","parameters":params,
        })
        if not executed["decision"]["effect_allowed"] or executed["upstream_hits"]!=1:
            raise RuntimeError("approved export did not execute exactly once")

        replay=post("/api/action",{
            "action":"export_restricted","principal":"service-account-17",
            "target":"document://SYNTHETIC/DOC-001","parameters":params,
        })
        if replay["decision"]["reason_code"]!="REPLAY_DETECTED" or replay["upstream_hits"]!=1:
            raise RuntimeError("approval replay was not blocked")

        evidence=get("/api/evidence")
        if not evidence.get("manifest") or not evidence.get("package_root"):
            raise RuntimeError("evidence manifest/package root missing")
        report=get("/api/report")
        if report.get("incident_id") is None: raise RuntimeError("incident report missing")

        print("HTTP_SMOKE_PASS")
        return 0
    finally:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()

if __name__=="__main__": raise SystemExit(main())
