"""Explainable deterministic detection rules for STF POC."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from typing import Any

@dataclass(frozen=True)
class Detection:
    rule_id:str
    reason_code:str
    severity:str
    score:int
    explanation:str
    entities:list[str]
    def to_dict(self): return asdict(self)

def evaluate(normalized:dict[str,Any]|None)->Detection|None:
    if not normalized: return None
    raw=normalized.get("raw") or {}
    cls=normalized.get("source_class")
    actor=str(normalized.get("actor","unknown"))
    asset=str(normalized.get("asset","unknown"))
    entities={actor,asset}
    for key in ("src_ip","source_ip","principal","host","src_host","dst_host","database","resource","dst_service"):
        v=raw.get(key)
        if v not in (None,"","unknown"): entities.add(str(v))

    if cls=="EDGE" and int(raw.get("waf_score",0))>=70:
        return Detection("DET-EDGE-001","EDGE_ANOMALY","MEDIUM",12,"Score sintético de borda acima do limiar documentado.",sorted(entities))
    if cls=="IDENTITY" and raw.get("context")=="new-device" and raw.get("device_trust")=="unknown":
        return Detection("DET-IAM-001","NEW_AUTH_CONTEXT","HIGH",18,"Identidade de serviço autenticou em contexto novo e não confiável.",sorted(entities))
    if cls=="HOST" and raw.get("process")=="synthetic-worker":
        return Detection("DET-HOST-001","UNUSUAL_PROCESS","HIGH",16,"Processo fora do baseline sintético do host.",sorted(entities))
    if cls=="NETWORK" and raw.get("src_host") and raw.get("dst_host") and raw.get("src_host")!=raw.get("dst_host"):
        return Detection("DET-NET-001","LATERAL_MOVEMENT","HIGH",14,"Conexão host-a-host não presente no baseline da conta fictícia.",sorted(entities))
    if cls=="DATABASE" and raw.get("operation")=="query" and int(raw.get("rows",0))>=40:
        return Detection("DET-DB-001","DB_BEHAVIOR_ANOMALY","HIGH",15,"Consulta com volume acima do baseline sintético do principal.",sorted(entities))
    if cls=="APPLICATION" and raw.get("classification")=="RESTRICTED":
        return Detection("DET-APP-001","RESTRICTED_RESOURCE_ACCESS","CRITICAL",20,"Identidade correlacionada acessou recurso classificado como restrito.",sorted(entities))
    return None

def rules_catalog()->list[dict[str,Any]]:
    return [
      {"rule_id":"DET-EDGE-001","source":"EDGE","reason":"EDGE_ANOMALY"},
      {"rule_id":"DET-IAM-001","source":"IDENTITY","reason":"NEW_AUTH_CONTEXT"},
      {"rule_id":"DET-HOST-001","source":"HOST","reason":"UNUSUAL_PROCESS"},
      {"rule_id":"DET-NET-001","source":"NETWORK","reason":"LATERAL_MOVEMENT"},
      {"rule_id":"DET-DB-001","source":"DATABASE","reason":"DB_BEHAVIOR_ANOMALY"},
      {"rule_id":"DET-APP-001","source":"APPLICATION","reason":"RESTRICTED_RESOURCE_ACCESS"},
    ]
