#!python
"""Independent offline verifier for STF POC Evidence Bundle."""
import argparse, hashlib, json
from pathlib import Path

def canonical_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(v): return hashlib.sha256(v if isinstance(v,(bytes,bytearray)) else canonical_bytes(v)).hexdigest()
def is_hex64(value):
    if not isinstance(value,str) or len(value)!=64: return False
    try: bytes.fromhex(value); return True
    except ValueError: return False
def merkle(hashes):
    if not hashes: return hashlib.sha256(b"").hexdigest()
    if not all(is_hex64(x) for x in hashes): raise ValueError("invalid hash")
    level=[bytes.fromhex(x) for x in hashes]
    while len(level)>1:
        if len(level)%2: level.append(level[-1])
        level=[hashlib.sha256(level[i]+level[i+1]).digest() for i in range(0,len(level),2)]
    return level[0].hex()

def verify(bundle):
    if not isinstance(bundle,dict):
        return {"structure":"FAIL","chain":"FAIL","merkle":"FAIL","manifest":"FAIL","package_root":"FAIL","semantic":"FAIL","overall":"FAIL"}
    events=bundle.get("events")
    if not isinstance(events,list):
        return {"structure":"FAIL","chain":"FAIL","merkle":"FAIL","manifest":"FAIL","package_root":"FAIL","semantic":"FAIL","overall":"FAIL"}

    prev="0"*64; hashes=[]; chain_ok=True
    for raw in events:
        if not isinstance(raw,dict):
            chain_ok=False; continue
        item=dict(raw); event_hash=item.pop("event_hash","")
        if item.get("prev_hash")!=prev: chain_ok=False
        if not is_hex64(event_hash) or sha(item)!=event_hash: chain_ok=False
        if is_hex64(event_hash): hashes.append(event_hash)
        prev=event_hash

    root_ok=False
    try:
        root_ok=len(hashes)==len(events) and merkle(hashes)==bundle.get("merkle_root")
    except ValueError:
        root_ok=False

    section_names=("metadata","events","signals","incident","attack_graph","qualification","trust","limitations")
    manifest=bundle.get("manifest") if isinstance(bundle.get("manifest"),dict) else {}
    manifest_ok=all(is_hex64(manifest.get(name)) and manifest.get(name)==sha(bundle.get(name)) for name in section_names)

    package_ok=False
    if manifest_ok:
        try:
            package_ok=is_hex64(bundle.get("package_root")) and merkle([manifest[name] for name in sorted(manifest)])==bundle.get("package_root")
        except ValueError:
            package_ok=False

    metadata=bundle.get("metadata") if isinstance(bundle.get("metadata"),dict) else {}
    metadata_keys=("schema_version","package_id","campaign_id","incident_id","generated_at_claimed","event_count","lsn_range","merkle_root")
    metadata_match=all(bundle.get(k)==metadata.get(k) for k in metadata_keys)

    semantic_ok=metadata_match
    semantic_ok=semantic_ok and bundle.get("event_count")==len(events)
    semantic_ok=semantic_ok and bundle.get("lsn_range")==([1,len(events)] if events else [0,0])
    semantic_ok=semantic_ok and [e.get("lsn") for e in events if isinstance(e,dict)]==list(range(1,len(events)+1))
    semantic_ok=semantic_ok and all(isinstance(e,dict) and e.get("campaign_id")==bundle.get("campaign_id") for e in events)
    top_incident_id=bundle.get("incident_id")
    semantic_ok=semantic_ok and all(e.get("incident_id") in (None,top_incident_id) for e in events if isinstance(e,dict))
    event_by_lsn={e.get("lsn"):e for e in events if isinstance(e,dict)}

    signals=bundle.get("signals") if isinstance(bundle.get("signals"),list) else []
    seen=set()
    for signal in signals:
        if not isinstance(signal,dict):
            semantic_ok=False; continue
        sid=signal.get("signal_id")
        if sid in seen: semantic_ok=False
        seen.add(sid)
        ev=event_by_lsn.get(signal.get("lsn"))
        if not ev or signal.get("campaign_id")!=bundle.get("campaign_id") or signal.get("evidence_hash")!=ev.get("event_hash"):
            semantic_ok=False

    incident=bundle.get("incident")
    if incident is not None:
        if not isinstance(incident,dict) or incident.get("incident_id")!=top_incident_id:
            semantic_ok=False
        else:
            evidence_lsns = incident.get("evidence_lsns")
            if isinstance(evidence_lsns, (list, tuple, set)):
                for lsn in evidence_lsns:
                    if lsn not in event_by_lsn: semantic_ok=False
            elif evidence_lsns is not None:
                semantic_ok=False

    structure=all(k in bundle for k in [
        "schema_version","package_id","campaign_id","incident_id","generated_at_claimed",
        "event_count","lsn_range","merkle_root","package_root","manifest","metadata",
        "events","signals","qualification","trust"
    ])
    overall=structure and chain_ok and root_ok and manifest_ok and package_ok and semantic_ok
    return {
        "structure":"PASS" if structure else "FAIL",
        "chain":"PASS" if chain_ok else "FAIL",
        "merkle":"PASS" if root_ok else "FAIL",
        "manifest":"PASS" if manifest_ok else "FAIL",
        "package_root":"PASS" if package_ok else "FAIL",
        "semantic":"PASS" if semantic_ok else "FAIL",
        "overall":"PASS" if overall else "FAIL",
        "event_count":len(events),
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("bundle",type=Path); args=ap.parse_args()
    try: bundle=json.loads(args.bundle.read_text(encoding="utf-8"))
    except Exception as e: print(json.dumps({"overall":"FAIL","error":str(e)},indent=2)); return 3
    try: result=verify(bundle)
    except Exception as e:
        result={"overall":"FAIL","error":f"verifier internal guard: {e}"}
    print(json.dumps(result,indent=2)); return 0 if result.get("overall")=="PASS" else 2

if __name__=="__main__": raise SystemExit(main())
