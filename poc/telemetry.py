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
    if not isinstance(raw,dict): raise ValueError("raw telemetry must be an object")
    missing=[k for k in keys if k not in raw]
    if missing: raise ValueError("missing fields: "+",".join(missing))

def _str(raw:dict[str,Any], key:str, *, default: str|None=None)->str:
    if key not in raw:
        if default is not None: return default
        raise ValueError(f"missing field: {key}")
    value=raw[key]
    if not isinstance(value,str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value.strip()

def _num(raw:dict[str,Any], key:str, *, default:int|float=0)->int|float:
    value=raw.get(key,default)
    if isinstance(value,bool) or not isinstance(value,(int,float)):
        raise ValueError(f"{key} must be numeric")
    return value

def _severity(raw:dict[str,Any], default:str)->str:
    value=raw.get("severity",default)
    if not isinstance(value,str): raise ValueError("severity must be a string")
    value=value.upper()
    if value not in {"INFO","LOW","MEDIUM","HIGH","CRITICAL"}:
        raise ValueError("unsupported severity")
    return value

def normalize_firewall(raw):
    _need(raw,"event_id","src_ip","dst_service","action")
    _num(raw,"waf_score",default=0)
    return CanonicalTelemetry(
        "EDGE","firewall-waf",_str(raw,"src_ip"),_str(raw,"dst_service"),
        "network.connection",_severity(raw,"MEDIUM"),_str(raw,"action"),_str(raw,"event_id"),raw
    )

def normalize_identity(raw):
    _need(raw,"event_id","principal","context","result")
    return CanonicalTelemetry(
        "IDENTITY","iam",_str(raw,"principal"),_str(raw,"tenant",default="identity-provider"),
        "identity.login",_severity(raw,"HIGH"),_str(raw,"result"),_str(raw,"event_id"),raw
    )

def normalize_host(raw):
    _need(raw,"event_id","principal","host","process")
    os_name=_str(raw,"os",default="linux").lower()
    return CanonicalTelemetry(
        "HOST",os_name,_str(raw,"principal"),_str(raw,"host"),
        "host.process",_severity(raw,"HIGH"),_str(raw,"result",default="OBSERVED"),_str(raw,"event_id"),raw
    )

def normalize_network(raw):
    _need(raw,"event_id","principal","src_host","dst_host")
    if "dst_port" in raw: _num(raw,"dst_port")
    return CanonicalTelemetry(
        "NETWORK","network",_str(raw,"principal"),_str(raw,"dst_host"),
        "network.lateral",_severity(raw,"HIGH"),_str(raw,"result",default="OBSERVED"),_str(raw,"event_id"),raw
    )

def normalize_db(raw):
    _need(raw,"event_id","principal","database","operation")
    if "rows" in raw: _num(raw,"rows")
    operation=_str(raw,"operation").lower()
    return CanonicalTelemetry(
        "DATABASE","db-audit",_str(raw,"principal"),_str(raw,"database"),
        "db."+operation,_severity(raw,"HIGH"),_str(raw,"result",default="OBSERVED"),_str(raw,"event_id"),raw
    )

def normalize_app(raw):
    _need(raw,"event_id","principal","resource","action")
    action=_str(raw,"action").lower()
    return CanonicalTelemetry(
        "APPLICATION","judicial-app-synthetic",_str(raw,"principal"),_str(raw,"resource"),
        "app."+action,_severity(raw,"CRITICAL"),_str(raw,"result",default="OBSERVED"),_str(raw,"event_id"),raw
    )

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
