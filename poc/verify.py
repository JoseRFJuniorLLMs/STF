#!/usr/bin/env python3
"""Independent offline verifier for STF POC Evidence Bundle."""
import argparse, hashlib, json
from pathlib import Path

def canonical_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(v): return hashlib.sha256(v if isinstance(v,(bytes,bytearray)) else canonical_bytes(v)).hexdigest()
def merkle(hashes):
    if not hashes: return hashlib.sha256(b"").hexdigest()
    level=[bytes.fromhex(x) for x in hashes]
    while len(level)>1:
        if len(level)%2: level.append(level[-1])
        level=[hashlib.sha256(level[i]+level[i+1]).digest() for i in range(0,len(level),2)]
    return level[0].hex()
def verify(bundle):
    events=bundle.get("events")
    if not isinstance(events,list): return {"structure":"FAIL","chain":"NOT_RUN","merkle":"NOT_RUN","overall":"FAIL"}
    prev="0"*64; hashes=[]; chain_ok=True
    for raw in events:
        if not isinstance(raw,dict): chain_ok=False; continue
        item=dict(raw); event_hash=item.pop("event_hash","")
        if item.get("prev_hash")!=prev or sha(item)!=event_hash: chain_ok=False
        if len(event_hash)!=64: chain_ok=False
        else: hashes.append(event_hash)
        prev=event_hash
    root_ok=merkle(hashes)==bundle.get("merkle_root")
    structure=all(k in bundle for k in ["schema_version","package_id","campaign_id","merkle_root","events","qualification","trust"])
    overall=structure and chain_ok and root_ok
    return {"structure":"PASS" if structure else "FAIL","chain":"PASS" if chain_ok else "FAIL","merkle":"PASS" if root_ok else "FAIL","overall":"PASS" if overall else "FAIL","event_count":len(events)}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("bundle",type=Path); args=ap.parse_args()
    try: bundle=json.loads(args.bundle.read_text(encoding="utf-8"))
    except Exception as e: print(json.dumps({"overall":"FAIL","error":str(e)},indent=2)); return 3
    result=verify(bundle); print(json.dumps(result,indent=2)); return 0 if result["overall"]=="PASS" else 2
if __name__=="__main__": raise SystemExit(main())
