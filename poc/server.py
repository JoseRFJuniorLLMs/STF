#!/usr/bin/env python3
"""STF POC - synthetic two-phase cyber campaign dashboard.

No external dependencies. No network calls. No offensive payloads.
The server intentionally binds to loopback by default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import subprocess
import sys
import tempfile
import threading
import time
from copy import deepcopy
from functools import wraps
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs
from telemetry import sample_campaign, normalize
from correlation import correlate
from detector import evaluate as detect_event
from policy import decide as policy_decide
from faults import simulate as simulate_fault
from synthetic_upstream import SyntheticUpstream

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
OUT = ROOT / "out"
OUT.mkdir(exist_ok=True)

CAMPAIGN_ID = "STF-POC-CAMPAIGN-001"
INCIDENT_ID = "STF-POC-INCIDENT-001"
SYNTHETIC_CASE = "case://SYNTHETIC/RE-000001"
COMPROMISED_PRINCIPAL = "service-account-17"
LOCAL_HOSTS={"127.0.0.1","localhost","::1"}

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(value: Any) -> str:
    data = value if isinstance(value, (bytes, bytearray)) else canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()

def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()

def locked_method(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return fn(self, *args, **kwargs)
    return wrapped

@dataclass
class EvidenceEvent:
    lsn: int
    hlc: int
    phase: str
    source: str
    event_type: str
    severity: str
    actor: str
    asset: str
    summary: str
    outcome: str
    campaign_id: str = CAMPAIGN_ID
    incident_id: str | None = None
    reason_code: str | None = None
    upstream_delta: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    event_hash: str = ""

    def material(self) -> dict[str, Any]:
        obj = asdict(self)
        obj.pop("event_hash", None)
        return obj

class PocEngine:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.upstream = SyntheticUpstream()
        self.reset()

    @property
    def upstream_hits(self) -> int:
        return self.upstream.hits

    def __del__(self) -> None:
        directory=getattr(self,"_scripted_export_dir",None)
        if directory is not None:
            directory.cleanup()

    def reset(self) -> None:
        with getattr(self, "lock", threading.RLock()):
            previous_export=getattr(self,"_scripted_export_dir",None)
            if previous_export is not None:
                previous_export.cleanup()
            self._scripted_export_dir: tempfile.TemporaryDirectory[str] | None = None
            self._scripted_export_path: Path | None = None
            self.events: list[EvidenceEvent] = []
            self.signals: list[dict[str, Any]] = []
            self.incident: dict[str, Any] | None = None
            self.attack_graph = {"nodes": [], "edges": []}
            self.step_index = 0
            self.execution_mode = "IDLE"
            self.risk = 0
            self.upstream.reset()
            self.pending_approval: dict[str, Any] | None = None
            self.approvals: dict[str, dict[str, Any]] = {}
            self.approvals_consumed: set[str] = set()
            self.raw_registry: dict[str, dict[str, Any]] = {}
            self.export_count = 0
            self.case_state = {
                "id": SYNTHETIC_CASE,
                "status": "ACTIVE",
                "classification": "RESTRICTED",
                "metadata_version": 1,
                "last_effect": "NONE",
            }
            self.tamper_status = "NOT_TESTED"
            self.offline_verify = "NOT_RUN"
            self.last_action = "Ambiente reiniciado"
            self._scenario = self._build_scenario()

    def _build_scenario(self) -> list[dict[str, Any]]:
        scenario = [
            {"phase":"FASE 1","source":"Firewall","type":"network.connection","severity":"INFO","actor":"external-client-42","asset":"edge","summary":"Tráfego benigno de referência aceito","outcome":"ALLOW","risk":0,"signal":False},
            {"phase":"FASE 1","source":"Firewall/WAF","type":"edge.suspicious","severity":"MEDIUM","actor":"ai-attacker-synthetic","asset":"public-edge","summary":"Padrão de acesso incomum observado no perímetro sintético","outcome":"OBSERVED","risk":12,"signal":True,"reason":"EDGE_ANOMALY"},
            {"phase":"FASE 1","source":"IAM","type":"identity.login","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"identity-provider","summary":"Autenticação em contexto novo para conta de serviço fictícia","outcome":"OBSERVED","risk":18,"signal":True,"reason":"NEW_AUTH_CONTEXT"},
            {"phase":"FASE 1","source":"Linux Host","type":"host.process","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"srv-app-07","summary":"Execução incomum em host de laboratório","outcome":"OBSERVED","risk":16,"signal":True,"reason":"UNUSUAL_PROCESS"},
            {"phase":"FASE 1","source":"Network","type":"network.lateral","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"srv-db-02","summary":"Conexão lateral sintética correlacionada ao mesmo principal","outcome":"OBSERVED","risk":14,"signal":True,"reason":"LATERAL_MOVEMENT"},
            {"phase":"FASE 1","source":"DB Audit","type":"db.query","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"db-judicial-lab","summary":"Consulta incomum fora do perfil sintético da identidade","outcome":"OBSERVED","risk":15,"signal":True,"reason":"DB_BEHAVIOR_ANOMALY"},
            {"phase":"FASE 1","source":"STF-Digital-like App","type":"app.resource_access","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":SYNTHETIC_CASE,"summary":"Acesso a recurso restrito correlacionado à campanha","outcome":"OBSERVED","risk":20,"signal":True,"reason":"RESTRICTED_RESOURCE_ACCESS"},
            {"phase":"FASE 2","source":"Policy Gateway","type":"app.case_update_requested","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":SYNTHETIC_CASE,"summary":"Tentativa de alterar metadados do processo fictício","outcome":"PENDING_POLICY","policy_action":"case_write","policy":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"agent.tool_requested","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Agente solicita exportação de documento restrito","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"approval":True},
            {"phase":"FASE 2","source":"HITL","type":"approval.granted","severity":"INFO","actor":"human:approver-01","asset":"document://SYNTHETIC/DOC-001","summary":"Aprovação humana vinculada à identidade, ação e parâmetros","outcome":"APPROVED","approve":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"tool.executed","severity":"MEDIUM","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Operação aprovada executada exatamente uma vez","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"execute":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"approval.replay","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Tentativa de reutilizar aprovação já consumida","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"replay":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"identity.swap","severity":"CRITICAL","actor":"agent:other-identity","asset":"document://SYNTHETIC/DOC-001","summary":"Outra identidade tenta usar autorização da campanha","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"approval_ref":"APR-001"},
            {"phase":"FASE 2","source":"Agent Gateway","type":"parameters.swap","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-999","summary":"Parâmetros são alterados depois da aprovação","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-999","format":"pdf"},"approval_ref":"APR-001"},
            {"phase":"FASE 2","source":"HRKL","type":"tamper.attempt","severity":"CRITICAL","actor":"ai-attacker-synthetic","asset":"evidence-log","summary":"Tentativa de modificar e reordenar evidência histórica","outcome":"DETECTED","reason":"MERKLE_ROOT_MISMATCH","tamper":True},
            {"phase":"FASE 2","source":"Evidence","type":"evidence.exported","severity":"INFO","actor":"service:evidence-exporter","asset":"evidence://STF-POC-001","summary":"Pacote de evidências gerado para verificação independente","outcome":"PASS","evidence":True},
            {"phase":"FASE 2","source":"Offline Verifier","type":"evidence.verified","severity":"INFO","actor":"service:offline-verifier","asset":"evidence://STF-POC-001","summary":"Integridade local verificada sem depender do sistema de origem","outcome":"PASS","verify":True},
        ]
        # Enrich the six suspicious Phase-1 steps with heterogeneous raw telemetry
        # and the canonical result produced by the adapter. Index 0 is benign baseline.
        for offset, (kind, raw) in enumerate(sample_campaign(), start=1):
            scenario[offset]["raw_telemetry"] = raw
            scenario[offset]["normalized_telemetry"] = normalize(kind, raw)
        return scenario

    def _append(self, spec: dict[str, Any], incident_id: str | None = None) -> EvidenceEvent:
        lsn = len(self.events) + 1
        prev = self.events[-1].event_hash if self.events else "0" * 64
        ev = EvidenceEvent(
            lsn=lsn, hlc=1_800_000_000_000 + lsn,
            phase=spec.get("phase", "FASE 1"), source=spec.get("source", "unknown"),
            event_type=spec.get("type", "event"), severity=spec.get("severity", "INFO"),
            actor=spec.get("actor", "unknown"), asset=spec.get("asset", "unknown"),
            summary=spec.get("summary", ""), outcome=spec.get("outcome", "OBSERVED"),
            incident_id=incident_id, reason_code=spec.get("reason"), upstream_delta=spec.get("upstream"),
            details={k:v for k,v in spec.items() if k not in {"phase","source","type","severity","actor","asset","summary","outcome","reason","upstream"}},
            prev_hash=prev,
        )
        ev.event_hash = sha256_hex(ev.material())
        self.events.append(ev)
        return ev

    def _add_graph(self, ev: EvidenceEvent) -> None:
        eid=f"event:{ev.lsn}"
        self.attack_graph["nodes"].append({"id":eid,"kind":"event","label":ev.event_type,"severity":ev.severity})
        for value,kind in [(ev.actor,"actor"),(ev.asset,"asset")]:
            nid=f"{kind}:{value}"
            if not any(n["id"]==nid for n in self.attack_graph["nodes"]):
                self.attack_graph["nodes"].append({"id":nid,"kind":kind,"label":value,"severity":"INFO"})
            self.attack_graph["edges"].append({"from":nid,"to":eid,"type":"OBSERVED_IN"})
        if self.incident and (
            ev.incident_id==self.incident["incident_id"]
            or ev.lsn in self.incident.get("evidence_lsns",[])
        ):
            iid=f"incident:{INCIDENT_ID}"
            if not any(n["id"]==iid for n in self.attack_graph["nodes"]):
                self.attack_graph["nodes"].append({"id":iid,"kind":"incident","label":INCIDENT_ID,"severity":self.incident["severity"]})
            self.attack_graph["edges"].append({"from":eid,"to":iid,"type":"PART_OF_INCIDENT"})

    def _signal(self, ev: EvidenceEvent, detection: Any) -> None:
        normalized=ev.details.get("normalized_telemetry",{}) if isinstance(ev.details,dict) else {}
        self.signals.append({
            "signal_id":f"SIG-{len(self.signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,"source":ev.source,
            "source_class":normalized.get("source_class",ev.source),
            "severity":detection.severity,"reason_code":detection.reason_code,
            "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
            "score":detection.score,"actor":ev.actor,"asset":ev.asset,
            "entities":list(detection.entities),
            "campaign_id":CAMPAIGN_ID,"evidence_hash":ev.event_hash,
        })

    @staticmethod
    def _principal_from_component(signals: list[dict[str, Any]], component: dict[str, Any]) -> str | None:
        ids=set(component.get("signal_ids",[]))
        subset=[s for s in signals if s.get("signal_id") in ids]
        for signal in subset:
            if signal.get("source_class")=="IDENTITY" and signal.get("actor"):
                return str(signal["actor"])
        counts: dict[str,int]={}
        for signal in subset:
            actor=str(signal.get("actor") or "")
            if actor and not actor.startswith(("203.","198.","192.","10.")):
                counts[actor]=counts.get(actor,0)+1
        return max(counts,key=counts.get) if counts else None

    @staticmethod
    def _anchored_component(corr: dict[str, Any], incident: dict[str, Any] | None) -> dict[str, Any] | None:
        if not incident:
            return corr.get("best")
        principal_entity=f"principal:{incident.get('principal')}"
        prior_ids=set(incident.get("correlation",{}).get("signal_ids",[]))
        matches=[
            x for x in corr.get("components",[])
            if principal_entity in set(x.get("entities",[]))
            and prior_ids.intersection(x.get("signal_ids",[]))
        ]
        if not matches:
            return None
        matches.sort(key=lambda x:(x.get("qualifies",False),x.get("score",0),len(x.get("signal_ids",[]))),reverse=True)
        return matches[0]

    def _component_for_incident(self, corr: dict[str, Any]) -> dict[str, Any] | None:
        return self._anchored_component(corr,self.incident)

    def _telemetry_incident_id(self, normalized: dict[str, Any], detection: Any) -> str | None:
        if not self.incident or detection is None:
            return None
        next_lsn=len(self.events)+1
        next_signal_id=f"SIG-{len(self.signals)+1:03d}"
        candidate={
            "signal_id":next_signal_id,"lsn":next_lsn,"hlc":1_800_000_000_000+next_lsn,
            "source_class":normalized.get("source_class"),"severity":detection.severity,
            "entities":list(detection.entities),
        }
        component=self._component_for_incident(correlate(self.signals+[candidate]))
        if component and component.get("qualifies") and next_signal_id in component.get("signal_ids",[]):
            return self.incident["incident_id"]
        return None

    def _maybe_open_incident(self) -> None:
        corr=correlate(self.signals)
        candidate=self._component_for_incident(corr)
        if self.incident is not None:
            if candidate and candidate.get("qualifies"):
                self.risk=int(candidate.get("score",0))
                self.incident["risk_score"]=self.risk
                self.incident["severity"]="CRITICAL" if self.risk >= 90 else "HIGH"
                self.incident["evidence_lsns"]=list(candidate.get("lsns",[]))
                self.incident["correlation"]=deepcopy(candidate)
                self.incident["correlation_explanation"]=corr["explanation"]
            return
        best=corr["best"]
        self.risk=int(best.get("score",0))
        if best.get("qualifies"):
            principal=self._principal_from_component(self.signals,best)
            if not principal:
                return
            self.incident={
                "incident_id":INCIDENT_ID,"campaign_id":CAMPAIGN_ID,"state":"OPEN",
                "severity":"CRITICAL" if best["score"] >= 90 else "HIGH",
                "risk_score":best["score"],"principal":principal,
                "summary":"Campanha multi-fonte correlacionada por entidades observáveis",
                "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
                "evidence_lsns":list(best["lsns"]),
                "correlation":deepcopy(best),
                "correlation_explanation":corr["explanation"],
            }
            self.last_action="Incidente correlacionado e aberto"

    def _matching_approval(self, action: str, principal: str, target: str, params_digest: str | None) -> dict[str, Any] | None:
        candidates=[
            a for a in self.approvals.values()
            if a.get("action")==action and a.get("principal")==principal
            and a.get("target")==target and a.get("parameters_digest")==params_digest
            and a.get("state") in {"PENDING","APPROVED","CONSUMED"}
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda a:a.get("created_at_epoch",0),reverse=True)
        return candidates[0]

    def _create_approval(self, action: str, principal: str, target: str, params_digest: str | None, approval_id: str) -> dict[str, Any]:
        now=time.time()
        approval={
            "approval_id":approval_id,"state":"PENDING","action":action,"principal":principal,
            "tool":"export_restricted_document" if action=="export_restricted" else action,
            "target":target,"parameters_digest":params_digest,"single_use":True,
            "created_at_epoch":now,"expires_at_epoch":now+300,"expires_in":"5m",
        }
        self.approvals[approval_id]=approval
        self.pending_approval=approval
        return approval

    def ingest_telemetry(self, kind: str, raw: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="SCRIPTED":
                return {"status":"MODE_CONFLICT","detail":"reset before switching from scripted to API lab","state":self.snapshot()}
            self.execution_mode="API_LAB"
            normalized=normalize(kind,raw)
            raw_key=f"{normalized['source_class']}:{normalized['raw_id']}"
            raw_digest=sha256_hex(raw)
            previous=self.raw_registry.get(raw_key)
            if previous:
                if previous["digest"]==raw_digest:
                    return {"status":"IDEMPOTENT","duplicate_of_lsn":previous["lsn"],"state":self.snapshot()}
                return {"status":"CONFLICT","raw_id":normalized["raw_id"],"existing_lsn":previous["lsn"],"state":self.snapshot()}
            detection=detect_event(normalized)
            source_names={
                "EDGE":"Firewall/WAF","IDENTITY":"IAM","HOST":"Linux Host",
                "NETWORK":"Network","DATABASE":"DB Audit","APPLICATION":"STF-Digital-like App",
            }
            source=source_names.get(normalized.get("source_class"),normalized.get("source_system","Telemetry"))
            spec={
                "phase":"FASE 1","source":source,"type":normalized.get("activity","telemetry.event"),
                "severity":detection.severity if detection else normalized.get("severity","INFO"),
                "actor":normalized.get("actor","unknown"),"asset":normalized.get("asset","unknown"),
                "summary":detection.explanation if detection else f"Telemetria {kind} normalizada sem sinal de segurança",
                "outcome":normalized.get("outcome","OBSERVED"),
                "raw_telemetry":deepcopy(raw),"normalized_telemetry":deepcopy(normalized),"ingest_mode":"external_loopback",
            }
            ev=self._append(spec,self._telemetry_incident_id(normalized,detection))
            self.raw_registry[raw_key]={"digest":raw_digest,"lsn":ev.lsn}
            if detection is not None:
                self._signal(ev,detection)
            self._maybe_open_incident()
            # Do not mutate incident_id/hash after persistence. The opening event is
            # associated through incident.evidence_lsns and the graph, preserving its hash.
            self._add_graph(ev)
            self.last_action=f"Telemetria externa local ingerida: {kind}"
            return {"status":"INGESTED","ingested":asdict(ev),"detection":detection.to_dict() if detection else None,"state":self.snapshot()}


    def submit_action(self, action: str, principal: str, target: str, parameters: dict[str, Any] | None = None, approval_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="IDLE":
                self.execution_mode="API_LAB"
            parameters=parameters or {}
            params_digest=sha256_hex(parameters)
            selected=self.approvals.get(approval_id) if approval_id else self._matching_approval(action,principal,target,params_digest)
            decision=policy_decide(
                action=action,incident=self.incident,principal=principal,target=target,
                parameters_digest=params_digest,approval=selected,consumed=self.approvals_consumed,
            )
            prior_hits=self.upstream.hits
            receipt=self.upstream.execute(action,principal,target,parameters) if decision.effect_allowed else None
            actual_delta=self.upstream.hits-prior_hits
            if action=="case_write":
                event_type="app.case_update_requested"; source="Policy Gateway"; severity="CRITICAL"
                summary="Ação externa local solicita escrita no processo sintético"
            elif action=="export_restricted":
                event_type="tool.executed" if decision.effect_allowed else "agent.tool_requested"
                source="Agent Gateway"; severity="HIGH" if decision.outcome!="DENY" else "CRITICAL"
                summary="Ação externa local solicita exportação de documento sintético restrito"
            else:
                event_type="policy.unknown_action"; source="Policy Gateway"; severity="CRITICAL"
                summary="Ação externa local não reconhecida pelo policy engine"
            spec={
                "phase":"FASE 2","source":source,"type":event_type,"severity":severity,
                "actor":principal,"asset":target,"summary":summary,
                "outcome":"PASS" if decision.effect_allowed else decision.outcome,
                "reason":decision.reason_code,"upstream":actual_delta,
                "policy_action":action,"policy_params":deepcopy(parameters),
                "policy_decision":decision.to_dict(),"ingest_mode":"external_loopback",
                "approval_id":selected.get("approval_id") if selected else None,
                "upstream_receipt":receipt,
            }
            ev=self._append(spec,INCIDENT_ID if self.incident else None)
            if decision.requires_human:
                existing=selected if selected and selected.get("state")=="PENDING" else None
                if existing is None:
                    selected=self._create_approval(action,principal,target,params_digest,f"APR-LAB-{ev.lsn:03d}")
                else:
                    self.pending_approval=existing
            if decision.effect_allowed:
                if selected:
                    selected["state"]="CONSUMED"
                    self.approvals_consumed.add(selected["approval_id"])
                    self.pending_approval=selected
                self.case_state["last_effect"]=receipt["effect_kind"]
            self._add_graph(ev)
            self.last_action=f"Policy externa local: {action} -> {spec['outcome']}"
            return {
                "event":asdict(ev),"decision":decision.to_dict(),
                "pending_approval":deepcopy(self.pending_approval),"upstream_hits":self.upstream_hits,
                "state":self.snapshot(),
            }

    def grant_approval(self, approval_id: str, approver: str) -> dict[str, Any]:
        with self.lock:
            approval=self.approvals.get(approval_id)
            if not approval:
                return {"status":"REJECT","reason":"APPROVAL_NOT_FOUND","pending_approval":deepcopy(self.pending_approval)}
            if approval.get("state")!="PENDING":
                return {"status":"REJECT","reason":"APPROVAL_NOT_PENDING","pending_approval":deepcopy(approval)}
            if time.time()>float(approval.get("expires_at_epoch",0)):
                approval["state"]="EXPIRED"
                return {"status":"REJECT","reason":"APPROVAL_EXPIRED","pending_approval":deepcopy(approval)}
            approval["state"]="APPROVED"; approval["approved_by"]=approver
            self.pending_approval=approval
            spec={
                "phase":"FASE 2","source":"HITL","type":"approval.granted","severity":"INFO",
                "actor":approver,"asset":approval["target"],
                "summary":"Aprovação humana sintética concedida via API local",
                "outcome":"APPROVED","reason":"HUMAN_APPROVAL_GRANTED",
                "approval_id":approval_id,"policy_action":approval.get("action"),"ingest_mode":"external_loopback",
            }
            ev=self._append(spec,INCIDENT_ID if self.incident else None)
            self._add_graph(ev); self.last_action=f"HITL aprovado: {approval_id}"
            return {"status":"APPROVED","event":asdict(ev),"pending_approval":deepcopy(approval),"state":self.snapshot()}

    @staticmethod
    def _offline_verify_file(path: Path | None) -> dict[str, Any]:
        if path is None or not path.is_file():
            return {"overall":"FAIL","error":"exported evidence file is unavailable"}
        try:
            completed=subprocess.run(
                [sys.executable,str(ROOT/"verify.py"),str(path)],
                capture_output=True,text=True,encoding="utf-8",timeout=10,check=False,
            )
            result=json.loads(completed.stdout)
            if not isinstance(result,dict):
                return {"overall":"FAIL","error":"offline verifier returned a non-object result"}
            if completed.returncode!=0:
                result["overall"]="FAIL"
            return result
        except (OSError,subprocess.TimeoutExpired,ValueError) as exc:
            return {"overall":"FAIL","error":str(exc)}

    @classmethod
    def _offline_verify_bundle(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        try:
            with tempfile.TemporaryDirectory(prefix="stf-poc-verify-") as directory:
                path=Path(directory)/"evidence.json"
                path.write_text(json.dumps(bundle,ensure_ascii=False),encoding="utf-8")
                return cls._offline_verify_file(path)
        except OSError as exc:
            return {"overall":"FAIL","error":str(exc)}

    def _scripted_tamper_check(self) -> dict[str, Any]:
        original=self.evidence_bundle()
        baseline=self._offline_verify_bundle(original)
        tampered=deepcopy(original)
        if not tampered["events"]:
            return {"status":"MISSED","baseline":baseline,"verification":{"overall":"FAIL","error":"no event to tamper"}}
        tampered["events"][0]["summary"]="EVENTO ADULTERADO"
        verification=self._offline_verify_bundle(tampered)
        status="DETECTED" if baseline.get("overall")=="PASS" and verification.get("overall")=="FAIL" else "MISSED"
        return {"status":status,"baseline":baseline,"verification":verification}

    def _scripted_export(self) -> dict[str, Any]:
        bundle=self.evidence_bundle()
        if self.verify_bundle(bundle)["overall"]!="PASS":
            return {"status":"FAIL","error":"pre-export integrity check failed"}
        directory=None
        try:
            directory=tempfile.TemporaryDirectory(prefix="stf-poc-export-")
            path=Path(directory.name)/"evidence.json"
            path.write_text(json.dumps(bundle,ensure_ascii=False,indent=2),encoding="utf-8")
            self._scripted_export_dir=directory
            self._scripted_export_path=path
            return {"status":"PASS","package_root":bundle["package_root"]}
        except OSError as exc:
            if directory is not None:
                directory.cleanup()
            return {"status":"FAIL","error":str(exc)}

    def step(self) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="API_LAB":
                return self.snapshot(message="Modo API Lab ativo; reinicie antes de usar o roteiro embutido")
            self.execution_mode="SCRIPTED"
            if self.step_index >= len(self._scenario):
                return self.snapshot(message="Campanha concluída")
            spec=dict(self._scenario[self.step_index]); self.step_index += 1
            tamper_result=None
            export_result=None
            offline_result=None
            if spec.get("tamper"):
                tamper_result=self._scripted_tamper_check()
                spec["outcome"]=tamper_result["status"]
                spec["reason"]="EVIDENCE_INTEGRITY_FAILURE" if spec["outcome"]=="DETECTED" else "TAMPER_NOT_DETECTED"
                spec["tamper_probe"]=tamper_result
            if spec.get("evidence"):
                export_result=self._scripted_export()
                spec["outcome"]=export_result["status"]
                spec["export_result"]=export_result
            if spec.get("verify"):
                offline_result=self._offline_verify_file(self._scripted_export_path)
                spec["outcome"]="PASS" if offline_result.get("overall")=="PASS" else "FAIL"
                spec["offline_verification"]=offline_result
            if spec.get("policy_action"):
                params=spec.get("policy_params") or {}
                params_digest=sha256_hex(params) if params else None
                decision=policy_decide(
                    action=spec["policy_action"],
                    incident=self.incident,
                    principal=spec.get("actor","unknown"),
                    target=spec.get("asset","unknown"),
                    parameters_digest=params_digest,
                    approval=self.approvals.get(spec.get("approval_ref")) if spec.get("approval_ref") else self._matching_approval(spec["policy_action"],spec.get("actor","unknown"),spec.get("asset","unknown"),params_digest),
                    consumed=self.approvals_consumed,
                )
                prior_hits=self.upstream.hits
                receipt=(
                    self.upstream.execute(spec["policy_action"],spec.get("actor","unknown"),
                                          spec.get("asset","unknown"),params)
                    if decision.effect_allowed and spec.get("execute") else None
                )
                spec["reason"]=decision.reason_code
                spec["policy_decision"]=decision.to_dict()
                spec["upstream"]=self.upstream.hits-prior_hits
                spec["upstream_receipt"]=receipt
                spec["outcome"]="PASS" if decision.effect_allowed and spec.get("execute") else decision.outcome
            incident_id=INCIDENT_ID if self.incident else None
            ev=self._append(spec,incident_id)
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is not None:
                self._signal(ev,detection)
            self._maybe_open_incident()
            if spec.get("approval"):
                self._create_approval(
                    "export_restricted",COMPROMISED_PRINCIPAL,"document://SYNTHETIC/DOC-001",
                    sha256_hex({"document":"DOC-001","format":"pdf"}),"APR-001"
                )
            if spec.get("approve") and self.pending_approval:
                self.pending_approval["state"]="APPROVED"; self.pending_approval["approved_by"]="human:approver-01"
            if spec.get("execute") and spec.get("upstream")==1:
                if self.pending_approval:
                    self.pending_approval["state"]="CONSUMED"; self.approvals_consumed.add(self.pending_approval["approval_id"])
                self.case_state["last_effect"]=receipt["effect_kind"]
            if tamper_result is not None: self.tamper_status=tamper_result["status"]
            if export_result is not None and export_result["status"]=="PASS": self.export_count+=1
            if offline_result is not None: self.offline_verify="PASS" if offline_result.get("overall")=="PASS" else "FAIL"
            self._add_graph(ev); self.last_action=spec["summary"]
            return self.snapshot(message=f"Executado passo {self.step_index}/{len(self._scenario)}")

    def run_all(self) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="API_LAB":
                return self.snapshot(message="Modo API Lab ativo; reinicie antes de executar a campanha roteirizada")
            self.execution_mode="SCRIPTED"
            while self.step_index < len(self._scenario):
                self.step()
            return self.snapshot(message="Campanha completa executada")

    @locked_method
    def qualification(self) -> list[dict[str, str]]:
        denied=[e for e in self.events if e.outcome=="DENY"]
        policy_events=[e for e in self.events if e.details.get("policy_decision")]
        reason_codes={e.reason_code for e in policy_events}
        tests=[
            ("PHASE1_TELEMETRY_INGEST",len({e.source for e in self.events if e.phase=="FASE 1"})>=5,"PASS"),
            ("PHASE1_RAW_TO_CANONICAL",sum(1 for e in self.events if e.details.get("normalized_telemetry"))>=6,"PASS"),
            ("PHASE1_RULE_ENGINE",len(self.signals)>=6 and all(s.get("rule_id") for s in self.signals),"PASS"),
            ("PHASE1_ENTITY_CORRELATION",bool(self.incident and self.incident.get("correlation",{}).get("qualifies")),"PASS"),
            ("PHASE1_RULE_DETECTION",len(self.signals)>=3,"PASS"),
            ("PHASE1_CROSS_SOURCE_CORRELATION",self.incident is not None,"PASS"),
            ("PHASE1_INCIDENT_GRAPH",any(n["kind"]=="incident" for n in self.attack_graph["nodes"]),"PASS"),
            ("PHASE2_POLICY_ENGINE",len(policy_events)>=4,"PASS"),
            ("PHASE2_HITL_SINGLE_USE",bool(self.approvals_consumed) and self.upstream_hits==1,"PASS"),
            ("PHASE2_UNAPPROVED_WRITE",any(e.event_type=="app.case_update_requested" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("PHASE2_REPLAY","REPLAY_DETECTED" in reason_codes,"DENY"),
            ("PHASE2_IDENTITY_SWAP","IDENTITY_BINDING_MISMATCH" in reason_codes,"DENY"),
            ("PHASE2_PARAMETER_SWAP","PARAMETERS_DIGEST_MISMATCH" in reason_codes,"DENY"),
            ("UPSTREAM_ON_DENY",all((e.upstream_delta in (None,0)) and not e.details.get("upstream_receipt") for e in denied)
             and self.upstream_hits==sum((e.upstream_delta or 0) for e in self.events),"0"),
            ("HISTORY_TAMPER",self.tamper_status=="DETECTED","DETECTED"),
            ("EVIDENCE_EXPORT",self.export_count>0,"PASS"),
            ("OFFLINE_VERIFY",self.offline_verify=="PASS","PASS"),
        ]
        return [{"id":i,"ok":ok,"expected":expected,"observed":expected if ok else "PENDING"} for i,ok,expected in tests]

    @locked_method
    def evidence_bundle(self) -> dict[str, Any]:
        event_dicts=[asdict(e) for e in self.events]
        event_hashes=[e.event_hash for e in self.events]
        event_root=merkle_root(event_hashes)
        metadata={
            "schema_version":"stf-poc-evidence/3",
            "package_id":"POC-STF-001",
            "campaign_id":CAMPAIGN_ID,
            "incident_id":self.incident.get("incident_id") if self.incident else None,
            "generated_at_claimed":"2026-09-23T20:00:00-03:00",
            "event_count":len(event_dicts),
            "lsn_range":[1,len(event_dicts)] if event_dicts else [0,0],
            "merkle_root":event_root,
        }
        trust={
            "local_content_integrity":"PASS" if event_dicts else "NOT_RUN",
            "external_timestamp":"NOT_CONFIGURED",
            "institutional_signature":"NOT_CONFIGURED",
            "institutional_trust":"UNVERIFIED",
        }
        limitations=[
            "Dados integralmente sintéticos",
            "Nenhuma conexão com infraestrutura real do STF",
            "Sem IAM, HSM ou trust anchor institucional",
        ]
        sections={
            "metadata":deepcopy(metadata),
            "events":event_dicts,
            "signals":deepcopy(self.signals),
            "incident":deepcopy(self.incident),
            "attack_graph":deepcopy(self.attack_graph),
            "qualification":deepcopy(self.qualification()),
            "trust":trust,
            "limitations":limitations,
        }
        manifest={name:sha256_hex(value) for name,value in sections.items()}
        package_root=merkle_root([manifest[name] for name in sorted(manifest)])
        return {**metadata,"metadata":deepcopy(metadata),"package_root":package_root,"manifest":manifest,**sections}

    def verify_bundle(self,bundle:dict[str,Any])->dict[str,Any]:
        def is_hex64(value:Any)->bool:
            if not isinstance(value,str) or len(value)!=64:
                return False
            try:
                bytes.fromhex(value)
                return True
            except ValueError:
                return False

        events=bundle.get("events",[])
        if not isinstance(events,list):
            return {
                "chain":"FAIL","merkle":"FAIL","manifest":"FAIL","package_root":"FAIL",
                "semantic":"FAIL","overall":"FAIL",
            }

        prev="0"*64
        hashes=[]
        chain_ok=True
        for raw in events:
            if not isinstance(raw,dict):
                chain_ok=False
                continue
            item=dict(raw)
            event_hash=item.pop("event_hash","")
            if item.get("prev_hash") != prev:
                chain_ok=False
            if not is_hex64(event_hash) or sha256_hex(item) != event_hash:
                chain_ok=False
            if is_hex64(event_hash):
                hashes.append(event_hash)
            prev=event_hash

        computed_root=None
        if len(hashes)==len(events):
            try: computed_root=merkle_root(hashes)
            except ValueError: computed_root=None
        root_ok=computed_root is not None and computed_root==bundle.get("merkle_root")

        section_names=("metadata","events","signals","incident","attack_graph","qualification","trust","limitations")
        manifest=bundle.get("manifest") if isinstance(bundle.get("manifest"),dict) else {}
        manifest_ok=all(
            is_hex64(manifest.get(name)) and manifest.get(name)==sha256_hex(bundle.get(name))
            for name in section_names
        )
        package_ok=False
        if manifest_ok:
            try:
                expected_package_root=merkle_root([manifest[name] for name in sorted(manifest)])
                package_ok=is_hex64(bundle.get("package_root")) and expected_package_root==bundle.get("package_root")
            except ValueError:
                package_ok=False

        metadata=bundle.get("metadata") if isinstance(bundle.get("metadata"),dict) else {}
        metadata_keys=("schema_version","package_id","campaign_id","incident_id","generated_at_claimed","event_count","lsn_range","merkle_root")
        metadata_match=all(bundle.get(k)==metadata.get(k) for k in metadata_keys)

        semantic_ok=metadata_match
        semantic_ok=semantic_ok and bundle.get("event_count")==len(events)
        expected_range=[1,len(events)] if events else [0,0]
        semantic_ok=semantic_ok and bundle.get("lsn_range")==expected_range
        semantic_ok=semantic_ok and [e.get("lsn") for e in events if isinstance(e,dict)]==list(range(1,len(events)+1))
        semantic_ok=semantic_ok and all(
            isinstance(e,dict) and e.get("campaign_id")==bundle.get("campaign_id")
            for e in events
        )
        top_incident_id=bundle.get("incident_id")
        semantic_ok=semantic_ok and all(
            e.get("incident_id") in (None,top_incident_id)
            for e in events if isinstance(e,dict)
        )
        signals=bundle.get("signals") if isinstance(bundle.get("signals"),list) else []
        event_by_lsn={e.get("lsn"):e for e in events if isinstance(e,dict)}
        seen_signal_ids=set()
        for signal in signals:
            if not isinstance(signal,dict):
                semantic_ok=False
                continue
            sid=signal.get("signal_id")
            if sid in seen_signal_ids:
                semantic_ok=False
            seen_signal_ids.add(sid)
            ev=event_by_lsn.get(signal.get("lsn"))
            if not ev or signal.get("campaign_id")!=bundle.get("campaign_id") or signal.get("evidence_hash")!=ev.get("event_hash"):
                semantic_ok=False
        incident=bundle.get("incident")
        if incident is not None:
            if not isinstance(incident,dict) or incident.get("incident_id")!=top_incident_id:
                semantic_ok=False
            else:
                for lsn in incident.get("evidence_lsns",[]):
                    if lsn not in event_by_lsn:
                        semantic_ok=False

        overall=chain_ok and root_ok and manifest_ok and package_ok and semantic_ok
        return {
            "chain":"PASS" if chain_ok else "FAIL",
            "merkle":"PASS" if root_ok else "FAIL",
            "manifest":"PASS" if manifest_ok else "FAIL",
            "package_root":"PASS" if package_ok else "FAIL",
            "semantic":"PASS" if semantic_ok else "FAIL",
            "overall":"PASS" if overall else "FAIL",
        }

    @locked_method
    def source_health(self) -> list[dict[str, Any]]:
        expected=[
            ("Firewall/WAF",{"Firewall","Firewall/WAF"}),("IAM",{"IAM"}),
            ("Host",{"Linux Host","Windows Host"}),("Network",{"Network"}),
            ("DB Audit",{"DB Audit"}),("Application",{"STF-Digital-like App"}),
            ("Agent Gateway",{"Agent Gateway","Policy Gateway","HITL"}),
            ("Evidence",{"HRKL","Evidence","Offline Verifier"}),
        ]
        seen={e.source for e in self.events}
        return [{
            "source":label,"status":"ACTIVE" if seen.intersection(aliases) else "WAITING",
            "events":sum(1 for e in self.events if e.source in aliases),
            "matched":sorted(seen.intersection(aliases)),
        } for label,aliases in expected]

    @locked_method
    def why_incident(self) -> dict[str, Any]:
        if not self.incident:
            return {"status":"NOT_OPEN","summary":"Ainda não há evidência suficiente para abrir o incidente.","reasons":[],"evidence_lsns":[]}
        ids=set(self.incident.get("correlation",{}).get("signal_ids",[]))
        reasons=[]
        for signal in self.signals:
            if signal.get("signal_id") not in ids:
                continue
            ev=next((e for e in self.events if e.lsn==signal.get("lsn")),None)
            if not ev:
                continue
            reasons.append({
                "signal_id":signal.get("signal_id"),"lsn":ev.lsn,"source":ev.source,
                "reason_code":signal["reason_code"],"severity":signal["severity"],
                "actor":signal["actor"],"asset":signal["asset"],"summary":ev.summary,
                "evidence_hash":signal["evidence_hash"],"event_hash":ev.event_hash,
                "hash_reference_valid":signal["evidence_hash"]==ev.event_hash,
            })
        return {
            "status":"OPEN","incident_id":self.incident["incident_id"],
            "principal":self.incident["principal"],"risk_score":self.incident["risk_score"],
            "qualification_rule":"typed-entity correlation + source diversity + temporal window",
            "summary":"O incidente foi aberto por um componente temporal de sinais ligados por entidades tipadas.",
            "reasons":reasons,"evidence_lsns":[x["lsn"] for x in reasons],
        }

    @locked_method
    def evidence_object(self, lsn:int)->dict[str,Any]:
        ev=next((e for e in self.events if e.lsn==lsn),None)
        if ev is None:
            return {"status":"NOT_FOUND","lsn":lsn}
        prev_ev=next((e for e in self.events if e.lsn==lsn-1),None)
        next_ev=next((e for e in self.events if e.lsn==lsn+1),None)
        current_hash_valid=sha256_hex(ev.material())==ev.event_hash
        previous_link_valid=ev.prev_hash==(prev_ev.event_hash if prev_ev else "0"*64)
        next_link_valid=(next_ev is None or next_ev.prev_hash==ev.event_hash)
        bundle_verify=self.verify_bundle(self.evidence_bundle())
        return {
            "status":"PASS" if current_hash_valid and previous_link_valid and next_link_valid else "FAIL",
            "event":asdict(ev),
            "provenance":{
                "previous_lsn":prev_ev.lsn if prev_ev else None,
                "previous_hash":prev_ev.event_hash if prev_ev else "0"*64,
                "current_hash":ev.event_hash,
                "next_lsn":next_ev.lsn if next_ev else None,
                "next_prev_hash":next_ev.prev_hash if next_ev else None,
                "content_hash_valid":current_hash_valid,
                "previous_link_valid":previous_link_valid,
                "next_link_valid":next_link_valid,
                "chain_link_valid":previous_link_valid and next_link_valid,
                "bundle_overall":bundle_verify["overall"],
            },
        }

    @staticmethod
    def _signals_from_events(events:list[EvidenceEvent])->list[dict[str,Any]]:
        signals=[]
        for ev in events:
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is None:
                continue
            signals.append({
                "signal_id":f"SIG-{len(signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,
                "source":ev.source,"source_class":normalized.get("source_class",ev.source),
                "severity":detection.severity,"reason_code":detection.reason_code,
                "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
                "score":detection.score,"actor":ev.actor,"asset":ev.asset,
                "entities":list(detection.entities),"campaign_id":CAMPAIGN_ID,
                "evidence_hash":ev.event_hash,
            })
        return signals

    @classmethod
    def _replay_incident_state(cls, events:list[EvidenceEvent])->tuple[list[dict[str,Any]],dict[str,Any]|None,int]:
        signals=[]
        incident=None
        risk=0
        for ev in events:
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is None:
                continue
            signals.append({
                "signal_id":f"SIG-{len(signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,
                "source":ev.source,"source_class":normalized.get("source_class",ev.source),
                "severity":detection.severity,"reason_code":detection.reason_code,
                "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
                "score":detection.score,"actor":ev.actor,"asset":ev.asset,
                "entities":list(detection.entities),"campaign_id":CAMPAIGN_ID,
                "evidence_hash":ev.event_hash,
            })
            corr=correlate(signals)
            if incident is None:
                best=corr["best"]
                risk=int(best.get("score",0))
                if best.get("qualifies"):
                    principal=cls._principal_from_component(signals,best)
                    if principal:
                        incident={
                            "incident_id":INCIDENT_ID,"campaign_id":CAMPAIGN_ID,"state":"OPEN",
                            "severity":"CRITICAL" if best["score"]>=90 else "HIGH",
                            "risk_score":best["score"],"principal":principal,
                            "summary":"Reconstrução AS-OF pelo mesmo correlador do runtime",
                            "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
                            "evidence_lsns":list(best.get("lsns",[])),
                            "correlation":deepcopy(best),"correlation_explanation":corr["explanation"],
                        }
            else:
                chosen=cls._anchored_component(corr,incident)
                if chosen and chosen.get("qualifies"):
                    risk=int(chosen.get("score",0))
                    incident["risk_score"]=risk
                    incident["severity"]="CRITICAL" if risk>=90 else "HIGH"
                    incident["evidence_lsns"]=list(chosen.get("lsns",[]))
                    incident["correlation"]=deepcopy(chosen)
                    incident["correlation_explanation"]=corr["explanation"]
        return signals,incident,risk

    @locked_method
    def as_of(self, lsn:int)->dict[str,Any]:
        lsn=max(0,min(int(lsn),len(self.events)))
        events=list(self.events[:lsn])
        signals,incident,risk=self._replay_incident_state(events)
        receipts=[
            e.details["upstream_receipt"] for e in events
            if isinstance(e.details,dict) and isinstance(e.details.get("upstream_receipt"),dict)
            and e.details["upstream_receipt"].get("status")=="EXECUTED"
        ]
        upstream=len(receipts)
        tamper_events=[e for e in events if e.event_type.startswith("tamper.")]
        tamper=tamper_events[-1].outcome if tamper_events else "NOT_TESTED"
        approval_state="NONE"
        for e in events:
            if e.outcome=="REQUIRE_HITL":
                approval_state="PENDING"
            elif e.event_type=="approval.granted":
                approval_state="APPROVED"
            elif e.details.get("policy_decision",{}).get("effect_allowed"):
                approval_state="CONSUMED"
        return {
            "as_of_lsn":lsn,"event_count":len(events),"risk":risk,
            "incident":incident,"signals":signals,"upstream_hits":upstream,
            "tamper_status":tamper,"approval_state":approval_state,
            "case_state":{
                "id":SYNTHETIC_CASE,"classification":"RESTRICTED",
                "last_effect":receipts[-1]["effect_kind"] if receipts else "NONE",
            },
            "merkle_root":merkle_root([e.event_hash for e in events]),
            "events":[asdict(e) for e in events],
        }

    @locked_method
    def tamper_variant(self, kind:str)->dict[str,Any]:
        bundle=deepcopy(self.evidence_bundle())
        events=bundle.get("events",[])
        if not events:
            return {"kind":kind,"status":"NOT_RUN","verification":{"overall":"NOT_RUN"}}
        if kind=="modify":
            events[0]["summary"]="EVENTO ADULTERADO"
        elif kind=="delete" and len(events)>2:
            del events[len(events)//2]
        elif kind=="reorder" and len(events)>2:
            events[1],events[2]=events[2],events[1]
        elif kind=="truncate":
            bundle["events"]=events[:-1]
        else:
            return {"kind":kind,"status":"REJECT","error":"kind must be modify, delete, reorder or truncate"}
        verification=self.verify_bundle(bundle)
        status="DETECTED" if verification["overall"]=="FAIL" else "MISSED"
        if status=="DETECTED":
            self.tamper_status="DETECTED"
            ev=self._append({
                "phase":"FASE 2","source":"HRKL","type":"tamper.validation","severity":"CRITICAL",
                "actor":"service:tamper-test","asset":"evidence://STF-POC-001",
                "summary":f"Sabotagem controlada {kind} detectada pelo verifier",
                "outcome":"DETECTED","reason":"EVIDENCE_INTEGRITY_FAILURE","tamper_kind":kind,
            },INCIDENT_ID if self.incident else None)
            self._add_graph(ev)
        return {"kind":kind,"status":status,"verification":verification}

    @locked_method
    def compare_as_of(self,from_lsn:int,to_lsn:int)->dict[str,Any]:
        left=self.as_of(from_lsn); right=self.as_of(to_lsn)
        def incident_state(x): return x["incident"]["state"] if x.get("incident") else "NONE"
        return {
            "from":left,"to":right,
            "delta":{
                "events":right["event_count"]-left["event_count"],
                "risk":right["risk"]-left["risk"],
                "upstream_hits":right["upstream_hits"]-left["upstream_hits"],
                "incident":incident_state(left)+" -> "+incident_state(right),
                "approval":left["approval_state"]+" -> "+right["approval_state"],
                "tamper":left["tamper_status"]+" -> "+right["tamper_status"],
                "case_effect":left["case_state"]["last_effect"]+" -> "+right["case_state"]["last_effect"],
            },
        }

    @locked_method
    def incident_report(self)->dict[str,Any]:
        why=self.why_incident()
        policy_events=[e for e in self.events if e.details.get("policy_decision")]
        reasons={e.reason_code for e in policy_events}
        return {
            "title":"Relatório Sintético de Incidente — STF POC","campaign_id":CAMPAIGN_ID,
            "incident_id":self.incident.get("incident_id") if self.incident else None,
            "executive_summary":(
                "Campanha sintética correlacionada a partir de telemetria multi-fonte; "
                "decisões de policy e approvals são auditadas no mesmo histórico."
                if self.incident else "Campanha ainda não atingiu o critério de correlação."
            ),
            "risk":self.risk,"sources":self.source_health(),"why":why,
            "controls":{
                "policy_enforcement":"PASS" if any(e.outcome=="DENY" for e in policy_events) else "PENDING",
                "hitl":"PASS" if self.approvals_consumed else "PENDING",
                "anti_replay":"PASS" if "REPLAY_DETECTED" in reasons else "PENDING",
                "tamper_detection":self.tamper_status,
                "offline_verification":self.offline_verify,
            },
            "limitations":[
                "Ambiente integralmente sintético.","Nenhuma conexão com infraestrutura real do STF.",
                "Detecção limitada à telemetria ingerida.","Bloqueio limitado a rotas sob enforcement.",
            ],
        }

    def record_export(self)->dict[str,Any]:
        with self.lock:
            export_ev=self._append({
                "phase":"FASE 2","source":"Evidence","type":"evidence.exported","severity":"INFO",
                "actor":"service:evidence-exporter","asset":"evidence://STF-POC-001",
                "summary":"Evidence Bundle exportado via API local","outcome":"PASS",
            },INCIDENT_ID if self.incident else None)
            self._add_graph(export_ev)
            pre_bundle=self.evidence_bundle()
            pre_verify=self.verify_bundle(pre_bundle)
            verifier_ev=self._append({
                "phase":"FASE 2","source":"Offline Verifier","type":"evidence.verified","severity":"INFO",
                "actor":"service:offline-verifier","asset":"evidence://STF-POC-001",
                "summary":"Bundle verificado localmente após exportação",
                "outcome":"PASS" if pre_verify["overall"]=="PASS" else "FAIL",
                "verified_package_root":pre_bundle.get("package_root"),
            },INCIDENT_ID if self.incident else None)
            self._add_graph(verifier_ev)
            final_bundle=self.evidence_bundle()
            final_verify=self.verify_bundle(final_bundle)
            self.offline_verify=final_verify["overall"]
            self.export_count+=1
            final_bundle=self.evidence_bundle()
            final_verify=self.verify_bundle(final_bundle)
            return {"bundle":final_bundle,"verification":final_verify}

    @locked_method
    def snapshot(self,message:str|None=None)->dict[str,Any]:
        bundle=self.evidence_bundle()
        verify=self.verify_bundle(bundle) if self.events else {
            "chain":"NOT_RUN","merkle":"NOT_RUN","manifest":"NOT_RUN",
            "package_root":"NOT_RUN","semantic":"NOT_RUN","overall":"NOT_RUN",
        }
        counts={"info":0,"medium":0,"high":0,"critical":0}
        for e in self.events:
            key=e.severity.lower()
            if key in counts: counts[key]+=1
        return {
            "campaign_id":CAMPAIGN_ID,"incident_id":self.incident.get("incident_id") if self.incident else None,
            "step":self.step_index,"total_steps":len(self._scenario),
            "completed":self.step_index>=len(self._scenario),"risk":self.risk,
            "incident":deepcopy(self.incident),"signals":deepcopy(self.signals),
            "events":[asdict(e) for e in self.events],"graph":deepcopy(self.attack_graph),
            "pending_approval":deepcopy(self.pending_approval),"approvals":deepcopy(self.approvals),
            "case_state":deepcopy(self.case_state),"upstream_hits":self.upstream_hits,
            "tamper_status":self.tamper_status,"offline_verify":self.offline_verify,
            "merkle_root":bundle["merkle_root"],"package_root":bundle["package_root"],
            "verification":verify,"qualification":deepcopy(self.qualification()),
            "severity_counts":counts,"source_health":deepcopy(self.source_health()),
            "why_incident":deepcopy(self.why_incident()),"last_action":self.last_action,
            "message":message or "OK","mode":"SYNTHETIC / LOOPBACK ONLY","execution_mode":self.execution_mode,
        }

ENGINE=PocEngine()

class Handler(BaseHTTPRequestHandler):
    server_version="STFPOC/1.0"
    def log_message(self,fmt:str,*args:Any)->None: print(f"[STF-POC] {self.address_string()} - {fmt % args}")
    def _json(self,obj:Any,status:int=200)->None:
        raw=json.dumps(obj,ensure_ascii=False,indent=2).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw)
    def _read_json_body(self,max_bytes:int=65536)->dict[str,Any]:
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: raise ValueError("invalid content length")
        if length<=0 or length>max_bytes: raise ValueError("body size out of bounds")
        raw=self.rfile.read(length)
        value=json.loads(raw.decode("utf-8"))
        if not isinstance(value,dict): raise ValueError("JSON body must be an object")
        return value
    def _mutation_allowed(self)->bool:
        host_header=self.headers.get("Host","")
        host=urlparse("//"+host_header).hostname
        if host not in LOCAL_HOSTS:
            return False
        origin=self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in LOCAL_HOSTS:
            return False
        return self.headers.get("X-STF-POC")=="1"
    def do_GET(self)->None:
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if path=="/api/state": return self._json(ENGINE.snapshot())
        if path=="/api/evidence": return self._json(ENGINE.evidence_bundle())
        if path=="/api/source-health": return self._json({"sources":ENGINE.source_health()})
        if path=="/api/why": return self._json(ENGINE.why_incident())
        if path=="/api/report": return self._json(ENGINE.incident_report())
        if path=="/api/asof":
            try: lsn=int(query.get("lsn",["0"])[0])
            except ValueError: return self._json({"error":"invalid_lsn"},400)
            return self._json(ENGINE.as_of(lsn))
        if path=="/api/compare":
            try:
                from_lsn=int(query.get("from",["0"])[0]); to_lsn=int(query.get("to",["0"])[0])
            except ValueError:
                return self._json({"error":"invalid_lsn"},400)
            return self._json(ENGINE.compare_as_of(from_lsn,to_lsn))
        if path=="/api/evidence/object":
            try: lsn=int(query.get("lsn",["0"])[0])
            except ValueError: return self._json({"error":"invalid_lsn"},400)
            obj=ENGINE.evidence_object(lsn)
            return self._json(obj,200 if obj.get("status")=="PASS" else 404)
        if path=="/api/evidence/download":
            bundle=ENGINE.evidence_bundle()
            raw=json.dumps(bundle,ensure_ascii=False,indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Disposition",'attachment; filename="evidence-stf-poc-001.json"')
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if path=="/api/report/download":
            report=ENGINE.incident_report()
            raw=json.dumps(report,ensure_ascii=False,indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Disposition",'attachment; filename="incident-report-stf-poc-001.json"')
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if path=="/api/health": return self._json({"status":"ok","mode":"loopback-only","campaign":CAMPAIGN_ID})
        if path=="/api/heraclitus-adapter":
            base=os.environ.get("HERACLITUS_URL")
            if not base:
                return self._json({"status":"NOT_CONFIGURED","expected_surfaces":["/sentinel/status","/api/v1/agent/status","/api/v1/agent/red-team/events"],"note":"Defina HERACLITUS_URL para um endpoint loopback."})
            try:
                from heraclitus_adapter import HeraclitusAdapter
                snapshot=HeraclitusAdapter(base).snapshot()
                return self._json({"status":snapshot["status"],"snapshot":snapshot})
            except Exception as e: return self._json({"status":"UNAVAILABLE","error":str(e)})
        return self._static(path)
    def do_POST(self)->None:
        if not self._mutation_allowed():
            return self._json({"error":"forbidden_mutation","detail":"local origin and X-STF-POC header required"},403)
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if path=="/api/telemetry":
            kind=query.get("kind",[""])[0]
            try:
                raw=self._read_json_body()
                result=ENGINE.ingest_telemetry(kind,raw)
                status=201 if result.get("status")=="INGESTED" else 200 if result.get("status")=="IDEMPOTENT" else 409
                return self._json(result,status)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_telemetry","detail":str(e)},400)
        if path=="/api/action":
            try:
                body=self._read_json_body()
                action=body.get("action")
                principal=body.get("principal",COMPROMISED_PRINCIPAL)
                target=body.get("target")
                parameters=body.get("parameters") or {}
                approval_id=body.get("approval_id")
                if not isinstance(action,str) or not action.strip(): raise ValueError("action must be a non-empty string")
                if not isinstance(principal,str) or not principal.strip(): raise ValueError("principal must be a non-empty string")
                if not isinstance(target,str) or not target.strip(): raise ValueError("target must be a non-empty string")
                if not isinstance(parameters,dict): raise ValueError("parameters must be an object")
                if approval_id is not None and (not isinstance(approval_id,str) or not approval_id.strip()): raise ValueError("approval_id must be a non-empty string when supplied")
                return self._json(ENGINE.submit_action(action.strip(),principal.strip(),target.strip(),parameters,approval_id.strip() if approval_id else None),200)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_action","detail":str(e)},400)
        if path=="/api/approval/grant":
            try:
                body=self._read_json_body()
                approval_id=body.get("approval_id")
                approver=body.get("approver","human:approver-api")
                if not isinstance(approval_id,str) or not approval_id.strip(): raise ValueError("approval_id must be a non-empty string")
                if not isinstance(approver,str) or not approver.strip(): raise ValueError("approver must be a non-empty string")
                result=ENGINE.grant_approval(approval_id.strip(),approver.strip())
                return self._json(result,200 if result.get("status")=="APPROVED" else 409)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_approval","detail":str(e)},400)
        if path=="/api/reset": ENGINE.reset(); return self._json(ENGINE.snapshot("Ambiente reiniciado"))
        if path=="/api/step": return self._json(ENGINE.step())
        if path=="/api/run": return self._json(ENGINE.run_all())
        if path=="/api/tamper-demo":
            kind=query.get("kind",["modify"])[0]
            return self._json(ENGINE.tamper_variant(kind))
        if path=="/api/fault-demo":
            kind=query.get("kind",["policy_store_down"])[0]
            return self._json(simulate_fault(kind))
        if path=="/api/export":
            result=ENGINE.record_export(); bundle=result["bundle"]; target=OUT/"evidence-stf-poc-001.json"
            target.write_text(json.dumps(bundle,ensure_ascii=False,indent=2),encoding="utf-8")
            return self._json({
                "status":result["verification"]["overall"],"path":target.name,
                "sha256":sha256_hex(target.read_bytes()),"verification":result["verification"],"bundle":bundle,
            })
        return self._json({"error":"not_found"},404)
    def _static(self,path:str)->None:
        rel="index.html" if path in ("/","") else path.lstrip("/")
        target=(DASHBOARD/rel).resolve()
        if DASHBOARD.resolve() not in target.parents and target != DASHBOARD.resolve(): return self._json({"error":"forbidden"},403)
        if not target.exists() or not target.is_file(): return self._json({"error":"not_found"},404)
        data=target.read_bytes(); ctype=mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)

def main()->None:
    ap=argparse.ArgumentParser(description="STF HeraclitusDB synthetic POC dashboard")
    ap.add_argument("--host",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8787); args=ap.parse_args()
    if args.host not in LOCAL_HOSTS: raise SystemExit("Safety gate: this POC binds only to loopback addresses")
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f"STF POC dashboard: http://{args.host}:{args.port}"); print("Safety mode: SYNTHETIC / LOOPBACK ONLY")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=="__main__": main()
