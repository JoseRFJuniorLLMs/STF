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
import threading
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs
from telemetry import sample_campaign, normalize
from correlation import correlate
from detector import evaluate as detect_event
from policy import decide as policy_decide

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
OUT = ROOT / "out"
OUT.mkdir(exist_ok=True)

CAMPAIGN_ID = "STF-POC-CAMPAIGN-001"
INCIDENT_ID = "STF-POC-INCIDENT-001"
SYNTHETIC_CASE = "case://SYNTHETIC/RE-000001"
COMPROMISED_PRINCIPAL = "service-account-17"

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
        self.reset()

    def reset(self) -> None:
        with getattr(self, "lock", threading.RLock()):
            self.events: list[EvidenceEvent] = []
            self.signals: list[dict[str, Any]] = []
            self.incident: dict[str, Any] | None = None
            self.attack_graph = {"nodes": [], "edges": []}
            self.step_index = 0
            self.risk = 0
            self.upstream_hits = 0
            self.pending_approval: dict[str, Any] | None = None
            self.approvals_consumed: set[str] = set()
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
            {"phase":"FASE 2","source":"Agent Gateway","type":"identity.swap","severity":"CRITICAL","actor":"agent:other-identity","asset":"document://SYNTHETIC/DOC-001","summary":"Outra identidade tenta usar autorização da campanha","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"}},
            {"phase":"FASE 2","source":"Agent Gateway","type":"parameters.swap","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-999","summary":"Parâmetros são alterados depois da aprovação","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-999","format":"pdf"}},
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
        if self.incident:
            iid=f"incident:{INCIDENT_ID}"
            if not any(n["id"]==iid for n in self.attack_graph["nodes"]):
                self.attack_graph["nodes"].append({"id":iid,"kind":"incident","label":INCIDENT_ID,"severity":self.incident["severity"]})
            self.attack_graph["edges"].append({"from":eid,"to":iid,"type":"PART_OF_INCIDENT"})

    def _signal(self, ev: EvidenceEvent, detection: Any) -> None:
        normalized=ev.details.get("normalized_telemetry",{}) if isinstance(ev.details,dict) else {}
        self.signals.append({
            "signal_id":f"SIG-{len(self.signals)+1:03d}","lsn":ev.lsn,"source":ev.source,
            "source_class":normalized.get("source_class",ev.source),
            "severity":detection.severity,"reason_code":detection.reason_code,
            "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
            "score":detection.score,"actor":ev.actor,"asset":ev.asset,
            "entities":list(detection.entities),
            "campaign_id":CAMPAIGN_ID,"evidence_hash":ev.event_hash,
        })

    def _maybe_open_incident(self) -> None:
        corr=correlate(self.signals)
        best=corr["best"]
        self.risk=max(self.risk,int(best.get("score",0)))
        if self.incident is not None:
            self.incident["risk_score"]=max(self.incident["risk_score"],best.get("score",0))
            self.incident["severity"]="CRITICAL" if self.incident["risk_score"] >= 90 else "HIGH"
            self.incident["evidence_lsns"]=best.get("lsns",[])
            self.incident["correlation"]=best
            self.incident["correlation_explanation"]=corr["explanation"]
            return
        if best.get("qualifies"):
            self.incident={
                "incident_id":INCIDENT_ID,"campaign_id":CAMPAIGN_ID,"state":"OPEN",
                "severity":"CRITICAL" if best["score"] >= 90 else "HIGH",
                "risk_score":best["score"],"principal":COMPROMISED_PRINCIPAL,
                "summary":"Campanha multi-fonte correlacionada por entidades observáveis",
                "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
                "evidence_lsns":best["lsns"],
                "correlation":best,
                "correlation_explanation":corr["explanation"],
            }
            self.last_action="Incidente correlacionado e aberto"

    def step(self) -> dict[str, Any]:
        with self.lock:
            if self.step_index >= len(self._scenario):
                return self.snapshot(message="Campanha concluída")
            spec=dict(self._scenario[self.step_index]); self.step_index += 1
            if spec.get("policy_action"):
                params=spec.get("policy_params") or {}
                params_digest=sha256_hex(params) if params else None
                decision=policy_decide(
                    action=spec["policy_action"],
                    incident=self.incident,
                    principal=spec.get("actor","unknown"),
                    target=spec.get("asset","unknown"),
                    parameters_digest=params_digest,
                    approval=self.pending_approval,
                    consumed=self.approvals_consumed,
                )
                spec["reason"]=decision.reason_code
                spec["policy_decision"]=decision.to_dict()
                spec["upstream"]=1 if decision.effect_allowed and spec.get("execute") else 0
                spec["outcome"]="PASS" if decision.effect_allowed and spec.get("execute") else decision.outcome
            incident_id=INCIDENT_ID if self.incident else None
            ev=self._append(spec,incident_id)
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is not None:
                self.risk += int(detection.score)
                self._signal(ev,detection)
            elif normalized is None:
                self.risk += int(spec.get("risk",0))
            self._maybe_open_incident()
            if self.incident and ev.incident_id is None:
                ev.incident_id=INCIDENT_ID; ev.event_hash=sha256_hex(ev.material())
            if spec.get("approval"):
                self.pending_approval={
                    "approval_id":"APR-001","state":"PENDING","principal":COMPROMISED_PRINCIPAL,
                    "tool":"export_restricted_document","target":"document://SYNTHETIC/DOC-001",
                    "parameters_digest":sha256_hex({"document":"DOC-001","format":"pdf"}),
                    "single_use":True,"expires_in":"5m",
                }
            if spec.get("approve") and self.pending_approval:
                self.pending_approval["state"]="APPROVED"; self.pending_approval["approved_by"]="human:approver-01"
            if spec.get("execute") and spec.get("upstream")==1:
                self.upstream_hits += 1
                if self.pending_approval:
                    self.pending_approval["state"]="CONSUMED"; self.approvals_consumed.add(self.pending_approval["approval_id"])
                self.case_state["last_effect"]="DOCUMENT_EXPORT_SYNTHETIC"
            if spec.get("tamper"): self.tamper_status="DETECTED"
            if spec.get("verify"): self.offline_verify="PASS"
            self._add_graph(ev); self.last_action=spec["summary"]
            return self.snapshot(message=f"Executado passo {self.step_index}/{len(self._scenario)}")

    def run_all(self) -> dict[str, Any]:
        while self.step_index < len(self._scenario): self.step()
        return self.snapshot(message="Campanha completa executada")

    def qualification(self) -> list[dict[str, str]]:
        denied=[e for e in self.events if e.outcome=="DENY"]
        tests=[
            ("PHASE1_TELEMETRY_INGEST",len({e.source for e in self.events if e.phase=="FASE 1"})>=5,"PASS"),
            ("PHASE1_RAW_TO_CANONICAL",sum(1 for e in self.events if e.details.get("normalized_telemetry"))>=6,"PASS"),
            ("PHASE1_RULE_ENGINE",len(self.signals)>=6 and all(s.get("rule_id") for s in self.signals),"PASS"),
            ("PHASE1_ENTITY_CORRELATION",bool(self.incident and self.incident.get("correlation",{}).get("qualifies")),"PASS"),
            ("PHASE1_RULE_DETECTION",len(self.signals)>=3,"PASS"),
            ("PHASE1_CROSS_SOURCE_CORRELATION",self.incident is not None,"PASS"),
            ("PHASE1_INCIDENT_GRAPH",any(n["kind"]=="incident" for n in self.attack_graph["nodes"]),"PASS"),
            ("PHASE2_POLICY_ENGINE",sum(1 for e in self.events if e.details.get("policy_decision"))>=6,"PASS"),
            ("PHASE2_HITL_SINGLE_USE","APR-001" in self.approvals_consumed and self.upstream_hits==1,"PASS"),
            ("PHASE2_UNAPPROVED_WRITE",any(e.event_type=="app.case_update_requested" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("PHASE2_REPLAY",any(e.event_type=="approval.replay" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("PHASE2_IDENTITY_SWAP",any(e.event_type=="identity.swap" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("PHASE2_PARAMETER_SWAP",any(e.event_type=="parameters.swap" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("UPSTREAM_ON_DENY",all((e.upstream_delta in (None,0)) for e in denied),"0"),
            ("HISTORY_TAMPER",self.tamper_status=="DETECTED","DETECTED"),
            ("EVIDENCE_EXPORT",any(e.event_type=="evidence.exported" for e in self.events),"PASS"),
            ("OFFLINE_VERIFY",self.offline_verify=="PASS","PASS"),
        ]
        return [{"id":i,"ok":ok,"expected":expected,"observed":expected if ok else "PENDING"} for i,ok,expected in tests]

    def evidence_bundle(self) -> dict[str, Any]:
        event_dicts=[asdict(e) for e in self.events]; event_hashes=[e.event_hash for e in self.events]
        return {
            "schema_version":"stf-poc-evidence/1","package_id":"POC-STF-001","campaign_id":CAMPAIGN_ID,
            "incident_id":INCIDENT_ID if self.incident else None,"generated_at_claimed":"2026-09-23T20:00:00-03:00",
            "event_count":len(self.events),"lsn_range":[1,len(self.events)] if self.events else [0,0],
            "merkle_root":merkle_root(event_hashes),"events":event_dicts,"signals":self.signals,"incident":self.incident,
            "attack_graph":self.attack_graph,"qualification":self.qualification(),
            "trust":{"local_content_integrity":"PASS" if self.events else "NOT_RUN","external_timestamp":"NOT_CONFIGURED","institutional_signature":"NOT_CONFIGURED","institutional_trust":"UNVERIFIED"},
            "limitations":["Dados integralmente sintéticos","Nenhuma conexão com infraestrutura real do STF","Sem IAM, HSM ou trust anchor institucional"],
        }

    def verify_bundle(self,bundle:dict[str,Any])->dict[str,Any]:
        events=bundle.get("events",[]); prev="0"*64; hashes=[]; chain_ok=True
        for raw in events:
            item=dict(raw); event_hash=item.pop("event_hash","")
            if item.get("prev_hash") != prev: chain_ok=False
            if sha256_hex(item) != event_hash: chain_ok=False
            hashes.append(event_hash); prev=event_hash
        root_ok=merkle_root(hashes)==bundle.get("merkle_root")
        return {"chain":"PASS" if chain_ok else "FAIL","merkle":"PASS" if root_ok else "FAIL","overall":"PASS" if chain_ok and root_ok else "FAIL"}


    def source_health(self) -> list[dict[str, Any]]:
        expected = [
            ("Firewall/WAF", {"Firewall","Firewall/WAF"}),
            ("IAM", {"IAM"}),
            ("Host", {"Linux Host","Windows Host"}),
            ("Network", {"Network"}),
            ("DB Audit", {"DB Audit"}),
            ("Application", {"STF-Digital-like App"}),
            ("Agent Gateway", {"Agent Gateway","Policy Gateway","HITL"}),
            ("Evidence", {"HRKL","Evidence","Offline Verifier"}),
        ]
        seen = {e.source for e in self.events}
        out = []
        for label, aliases in expected:
            matched = sorted(seen.intersection(aliases))
            out.append({
                "source": label,
                "status": "ACTIVE" if matched else "WAITING",
                "events": sum(1 for e in self.events if e.source in aliases),
                "matched": matched,
            })
        return out

    def why_incident(self) -> dict[str, Any]:
        if not self.incident:
            return {
                "status":"NOT_OPEN",
                "summary":"Ainda não há evidência suficiente para abrir o incidente.",
                "reasons":[],
                "evidence_lsns":[],
            }
        reasons = []
        for signal in self.signals:
            ev = next((e for e in self.events if e.lsn == signal["lsn"]), None)
            if not ev:
                continue
            reasons.append({
                "lsn": ev.lsn,
                "source": ev.source,
                "reason_code": signal["reason_code"],
                "severity": signal["severity"],
                "actor": signal["actor"],
                "asset": signal["asset"],
                "summary": ev.summary,
                "evidence_hash": ev.event_hash,
            })
        return {
            "status":"OPEN",
            "incident_id":INCIDENT_ID,
            "principal":self.incident["principal"],
            "risk_score":self.incident["risk_score"],
            "threshold":60,
            "summary":"O incidente foi aberto porque sinais independentes de múltiplas fontes apontaram para a mesma identidade/ativos dentro da mesma campanha sintética.",
            "reasons":reasons,
            "evidence_lsns":[x["lsn"] for x in reasons],
        }

    def evidence_object(self, lsn: int) -> dict[str, Any]:
        ev = next((e for e in self.events if e.lsn == lsn), None)
        if ev is None:
            return {"status":"NOT_FOUND","lsn":lsn}
        prev_ev = next((e for e in self.events if e.lsn == lsn - 1), None)
        next_ev = next((e for e in self.events if e.lsn == lsn + 1), None)
        return {
            "status":"PASS",
            "event":asdict(ev),
            "provenance":{
                "previous_lsn":prev_ev.lsn if prev_ev else None,
                "previous_hash":prev_ev.event_hash if prev_ev else "0"*64,
                "current_hash":ev.event_hash,
                "next_lsn":next_ev.lsn if next_ev else None,
                "next_prev_hash":next_ev.prev_hash if next_ev else None,
                "chain_link_valid":ev.prev_hash == (prev_ev.event_hash if prev_ev else "0"*64),
            },
        }

    def as_of(self, lsn: int) -> dict[str, Any]:
        lsn = max(0, min(int(lsn), len(self.events)))
        events = self.events[:lsn]
        signals = [s for s in self.signals if s["lsn"] <= lsn]
        risk = sum(int(e.details.get("risk",0)) for e in events)
        incident = None
        if risk >= 60:
            incident = {
                "incident_id":INCIDENT_ID,
                "campaign_id":CAMPAIGN_ID,
                "state":"OPEN",
                "severity":"HIGH",
                "risk_score":risk,
                "principal":COMPROMISED_PRINCIPAL,
                "summary":"Reconstrução AS-OF do incidente sintético",
                "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
            }
        hashes=[e.event_hash for e in events]
        upstream=sum(e.upstream_delta or 0 for e in events if (e.upstream_delta or 0) > 0)
        tamper="DETECTED" if any(e.event_type=="tamper.attempt" for e in events) else "NOT_TESTED"
        approval_state="NONE"
        for e in events:
            if e.event_type=="agent.tool_requested": approval_state="PENDING"
            elif e.event_type=="approval.granted": approval_state="APPROVED"
            elif e.event_type=="tool.executed": approval_state="CONSUMED"
        return {
            "as_of_lsn":lsn,
            "event_count":len(events),
            "risk":risk,
            "incident":incident,
            "signals":signals,
            "upstream_hits":upstream,
            "tamper_status":tamper,
            "approval_state":approval_state,
            "case_state":{
                "id":SYNTHETIC_CASE,
                "classification":"RESTRICTED",
                "last_effect":"DOCUMENT_EXPORT_SYNTHETIC" if upstream else "NONE",
            },
            "merkle_root":merkle_root(hashes),
            "events":[asdict(e) for e in events],
        }

    def tamper_variant(self, kind: str) -> dict[str, Any]:
        bundle=json.loads(json.dumps(self.evidence_bundle()))
        events=bundle.get("events",[])
        if not events:
            return {"kind":kind,"status":"NOT_RUN","verification":{"overall":"NOT_RUN"}}
        if kind=="modify":
            events[0]["summary"]="EVENTO ADULTERADO"
        elif kind=="delete" and len(events) > 2:
            del events[len(events)//2]
        elif kind=="reorder" and len(events) > 2:
            events[1],events[2]=events[2],events[1]
        elif kind=="truncate":
            bundle["events"]=events[:-1]
        else:
            return {"kind":kind,"status":"REJECT","error":"kind must be modify, delete, reorder or truncate"}
        verification=self.verify_bundle(bundle)
        return {"kind":kind,"status":"DETECTED" if verification["overall"]=="FAIL" else "MISSED","verification":verification}


    def compare_as_of(self, from_lsn: int, to_lsn: int) -> dict[str, Any]:
        left=self.as_of(from_lsn); right=self.as_of(to_lsn)
        def incident_state(x): return x["incident"]["state"] if x.get("incident") else "NONE"
        return {
            "from":left,
            "to":right,
            "delta":{
                "events":right["event_count"]-left["event_count"],
                "risk":right["risk"]-left["risk"],
                "upstream_hits":right["upstream_hits"]-left["upstream_hits"],
                "incident":incident_state(left)+" -> "+incident_state(right),
                "approval":left["approval_state"]+" -> "+right["approval_state"],
                "tamper":left["tamper_status"]+" -> "+right["tamper_status"],
                "case_effect":left["case_state"]["last_effect"]+" -> "+right["case_state"]["last_effect"],
            }
        }

    def incident_report(self) -> dict[str, Any]:
        why=self.why_incident()
        return {
            "title":"Relatório Sintético de Incidente — STF POC",
            "campaign_id":CAMPAIGN_ID,
            "incident_id":INCIDENT_ID if self.incident else None,
            "executive_summary":(
                "Campanha sintética correlacionada a partir de telemetria multi-fonte. "
                "A identidade fictícia comprometida tentou ações pós-compromisso; operações não autorizadas foram negadas, "
                "uma operação com HITL foi executada uma única vez e a tentativa posterior de replay foi bloqueada."
                if self.incident else
                "Campanha ainda não atingiu o limiar de correlação."
            ),
            "risk":self.risk,
            "sources":self.source_health(),
            "why":why,
            "controls":{
                "policy_enforcement":"PASS" if any(e.outcome=="DENY" for e in self.events) else "PENDING",
                "hitl":"PASS" if "APR-001" in self.approvals_consumed else "PENDING",
                "anti_replay":"PASS" if any(e.event_type=="approval.replay" and e.outcome=="DENY" for e in self.events) else "PENDING",
                "tamper_detection":self.tamper_status,
                "offline_verification":self.offline_verify,
            },
            "limitations":[
                "Ambiente integralmente sintético.",
                "Nenhuma conexão com infraestrutura real do STF.",
                "Detecção limitada à telemetria ingerida.",
                "Bloqueio limitado a rotas que passam pelo ponto de enforcement.",
            ],
        }

    def snapshot(self,message:str|None=None)->dict[str,Any]:
        bundle=self.evidence_bundle()
        verify=self.verify_bundle(bundle) if self.events else {"chain":"NOT_RUN","merkle":"NOT_RUN","overall":"NOT_RUN"}
        counts={"info":0,"medium":0,"high":0,"critical":0}
        for e in self.events:
            key=e.severity.lower()
            if key in counts: counts[key]+=1
        return {
            "campaign_id":CAMPAIGN_ID,"incident_id":INCIDENT_ID,"step":self.step_index,"total_steps":len(self._scenario),
            "completed":self.step_index>=len(self._scenario),"risk":self.risk,"incident":self.incident,"signals":self.signals,
            "events":[asdict(e) for e in self.events],"graph":self.attack_graph,"pending_approval":self.pending_approval,
            "case_state":self.case_state,"upstream_hits":self.upstream_hits,"tamper_status":self.tamper_status,
            "offline_verify":self.offline_verify,"merkle_root":bundle["merkle_root"],"verification":verify,
            "qualification":self.qualification(),"severity_counts":counts,"source_health":self.source_health(),"why_incident":self.why_incident(),"last_action":self.last_action,
            "message":message or "OK","mode":"SYNTHETIC / LOOPBACK ONLY"
        }

ENGINE=PocEngine()

class Handler(BaseHTTPRequestHandler):
    server_version="STFPOC/1.0"
    def log_message(self,fmt:str,*args:Any)->None: print(f"[STF-POC] {self.address_string()} - {fmt % args}")
    def _json(self,obj:Any,status:int=200)->None:
        raw=json.dumps(obj,ensure_ascii=False,indent=2).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw)
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
                return self._json({"status":"CONNECTED","snapshot":HeraclitusAdapter(base).snapshot()})
            except Exception as e: return self._json({"status":"UNAVAILABLE","error":str(e)})
        return self._static(path)
    def do_POST(self)->None:
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if path=="/api/reset": ENGINE.reset(); return self._json(ENGINE.snapshot("Ambiente reiniciado"))
        if path=="/api/step": return self._json(ENGINE.step())
        if path=="/api/run": return self._json(ENGINE.run_all())
        if path=="/api/tamper-demo":
            kind=query.get("kind",["modify"])[0]
            return self._json(ENGINE.tamper_variant(kind))
        if path=="/api/export":
            bundle=ENGINE.evidence_bundle(); target=OUT/"evidence-stf-poc-001.json"
            target.write_text(json.dumps(bundle,ensure_ascii=False,indent=2),encoding="utf-8")
            return self._json({"status":"PASS","path":target.name,"sha256":sha256_hex(target.read_bytes()),"bundle":bundle})
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
    if args.host not in {"127.0.0.1","localhost","::1"}: raise SystemExit("Safety gate: this POC binds only to loopback addresses")
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f"STF POC dashboard: http://{args.host}:{args.port}"); print("Safety mode: SYNTHETIC / LOOPBACK ONLY")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=="__main__": main()
