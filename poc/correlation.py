"""Deterministic cross-source correlation for the synthetic STF POC.

This is intentionally explainable: signals are connected only when they share
observable entities (principal, IP, host, resource, etc.). No ML black box.
"""
from __future__ import annotations
from collections import defaultdict, deque
from typing import Any

SEVERITY_WEIGHT={"INFO":1,"LOW":2,"MEDIUM":4,"HIGH":7,"CRITICAL":10}

def _entities(signal:dict[str,Any])->set[str]:
    return {str(x) for x in signal.get("entities",[]) if x not in (None,"","unknown")}

def components(signals:list[dict[str,Any]])->list[list[int]]:
    n=len(signals)
    if not n: return []
    entity_index=defaultdict(list)
    for i,s in enumerate(signals):
        for e in _entities(s): entity_index[e].append(i)
    adj=[set() for _ in range(n)]
    for ids in entity_index.values():
        for i in ids:
            adj[i].update(j for j in ids if j!=i)
    seen=set(); out=[]
    for start in range(n):
        if start in seen: continue
        q=deque([start]); seen.add(start); comp=[]
        while q:
            i=q.popleft(); comp.append(i)
            for j in adj[i]:
                if j not in seen: seen.add(j); q.append(j)
        out.append(sorted(comp))
    return out

def score_component(signals:list[dict[str,Any]], ids:list[int])->dict[str,Any]:
    subset=[signals[i] for i in ids]
    source_classes={s.get("source_class") or s.get("source") for s in subset}
    entities=set().union(*(_entities(s) for s in subset)) if subset else set()
    severity=sum(SEVERITY_WEIGHT.get(str(s.get("severity","INFO")).upper(),1) for s in subset)
    # Score rewards corroboration, not raw event volume.
    score=min(100, len(subset)*7 + len(source_classes)*8 + min(severity,30))
    required={"IDENTITY","HOST","NETWORK"}
    has_core=required.issubset(source_classes)
    has_data=bool({"DATABASE","APPLICATION"}.intersection(source_classes))
    qualifies=len(subset)>=4 and len(source_classes)>=4 and has_core
    # Once DB/App appears, confidence rises but incident can open before that.
    confidence="HIGH" if qualifies and has_data else "MEDIUM" if qualifies else "LOW"
    return {
        "signal_ids":[s.get("signal_id") for s in subset],
        "lsns":[s.get("lsn") for s in subset],
        "sources":sorted(str(x) for x in source_classes),
        "entities":sorted(entities),
        "score":score,
        "confidence":confidence,
        "qualifies":qualifies,
        "has_data_plane_evidence":has_data,
    }

def correlate(signals:list[dict[str,Any]])->dict[str,Any]:
    ranked=[score_component(signals,ids) for ids in components(signals)]
    ranked.sort(key=lambda x:(x["qualifies"],x["score"],len(x["signal_ids"])),reverse=True)
    best=ranked[0] if ranked else {
        "signal_ids":[],"lsns":[],"sources":[],"entities":[],"score":0,
        "confidence":"LOW","qualifies":False,"has_data_plane_evidence":False,
    }
    return {
        "best":best,
        "components":ranked,
        "explanation":(
            f"{len(best['signal_ids'])} sinais conectados por entidades observáveis em "
            f"{len(best['sources'])} classes de fonte; confidence={best['confidence']}."
        ),
    }
