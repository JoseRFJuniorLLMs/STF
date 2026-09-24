#!/usr/bin/env python3
"""Portable loopback HTTP smoke test for STF POC."""
from __future__ import annotations
import json, pathlib, subprocess, sys, time, urllib.request

ROOT=pathlib.Path(__file__).resolve().parent
PORT=18787
BASE=f"http://127.0.0.1:{PORT}"

def get(path):
    with urllib.request.urlopen(BASE+path,timeout=2) as r:
        return json.loads(r.read().decode())

def post(path):
    req=urllib.request.Request(BASE+path,data=b"{}",method="POST",headers={"Content-Type":"application/json"})
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
        state=get("/api/state")
        if state["step"]!=0: raise RuntimeError("fresh state step != 0")
        stepped=post("/api/step")
        if stepped["step"]!=1 or len(stepped["events"])!=1: raise RuntimeError("step endpoint failed")
        if get("/api/evidence").get("event_count")!=1: raise RuntimeError("evidence endpoint failed")
        print("HTTP_SMOKE_PASS")
        return 0
    finally:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill()
if __name__=="__main__": raise SystemExit(main())
