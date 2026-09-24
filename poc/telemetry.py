"""Vendor-neutral synthetic telemetry adapters for STF POC.

Transforms heterogeneous raw lab events into one canonical envelope.
All addresses/identities are documentation-safe or synthetic.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class CanonicalTelemetry:
    source_class: str
    source_system: str
    actor: str
    asset: str
    activity: str
    severity: str
    outcome: str
    raw_id: str
    raw: dict[str, Any]

    def to_dict(self): return asdict(self)

def _need(raw:dict[str,Any], *keys:str):
    missing=[k for k in keys if k not in raw]
    if missing: raise ValueError("missing fields: "+",".join(missing))

def normalize_firewall(raw):
    _need(raw,"event_id","src_ip","dst_service","action")
    return CanonicalTelemetry("EDGE","firewall-waf",raw["src_ip"],raw["dst_service"],"network.connection",raw.get("severity","MEDIUM"),raw["action"],raw["event_id"],raw)

def normalize_identity(raw):
    _need(raw,"event_id","principal","context","result")
    return CanonicalTelemetry("IDENTITY","iam",raw["principal"],raw.get("tenant","identity-provider"),"identity.login",raw.get("severity","HIGH"),raw["result"],raw["event_id"],raw)

def normalize_host(raw):
    _need(raw,"event_id","principal","host","process")
    return CanonicalTelemetry("HOST",raw.get("os","linux").lower(),raw["principal"],raw["host"],"host.process",raw.get("severity","HIGH"),raw.get("result","OBSERVED"),raw["event_id"],raw)

def normalize_network(raw):
    _need(raw,"event_id","principal","src_host","dst_host")
    return CanonicalTelemetry("NETWORK","network",raw["principal"],raw["dst_host"],"network.lateral",raw.get("severity","HIGH"),raw.get("result","OBSERVED"),raw["event_id"],raw)

def normalize_db(raw):
    _need(raw,"event_id","principal","database","operation")
    return CanonicalTelemetry("DATABASE","db-audit",raw["principal"],raw["database"],"db."+raw["operation"].lower(),raw.get("severity","HIGH"),raw.get("result","OBSERVED"),raw["event_id"],raw)

def normalize_app(raw):
    _need(raw,"event_id","principal","resource","action")
    return CanonicalTelemetry("APPLICATION","judicial-app-synthetic",raw["principal"],raw["resource"],"app."+raw["action"].lower(),raw.get("severity","CRITICAL"),raw.get("result","OBSERVED"),raw["event_id"],raw)

ADAPTERS={"firewall":normalize_firewall,"identity":normalize_identity,"host":normalize_host,"network":normalize_network,"db":normalize_db,"app":normalize_app}

def normalize(kind:str, raw:dict[str,Any])->dict[str,Any]:
    if kind not in ADAPTERS: raise ValueError("unsupported telemetry kind: "+kind)
    return ADAPTERS[kind](raw).to_dict()

def sample_campaign():
    return [
      ("firewall",{"event_id":"RAW-FW-001","src_ip":"203.0.113.42","dst_service":"portal-synthetic","action":"OBSERVED","severity":"MEDIUM","waf_score":71}),
      ("identity",{"event_id":"RAW-IAM-002","principal":"service-account-17","source_ip":"203.0.113.42","context":"new-device","result":"OBSERVED","severity":"HIGH","mfa":"not-applicable","device_trust":"unknown"}),
      ("host",{"event_id":"RAW-HOST-003","principal":"service-account-17","host":"srv-app-07","process":"synthetic-worker","os":"Linux","severity":"HIGH","parent":"app-service"}),
      ("network",{"event_id":"RAW-NET-004","principal":"service-account-17","src_host":"srv-app-07","dst_host":"srv-db-02","dst_port":5432,"severity":"HIGH"}),
      ("db",{"event_id":"RAW-DB-005","principal":"service-account-17","database":"db-judicial-lab","operation":"query","object":"synthetic_case_metadata","rows":47,"severity":"HIGH"}),
      ("app",{"event_id":"RAW-APP-006","principal":"service-account-17","resource":"case://SYNTHETIC/RE-000001","action":"resource_access","classification":"RESTRICTED","severity":"CRITICAL"}),
    ]
