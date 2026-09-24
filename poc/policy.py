"""Fail-closed policy engine for the synthetic STF POC."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from typing import Any

@dataclass(frozen=True)
class PolicyDecision:
    outcome:str
    reason_code:str
    effect_allowed:bool
    requires_human:bool
    explanation:str
    def to_dict(self): return asdict(self)

def decide(*,action:str,incident:dict[str,Any]|None,principal:str,target:str,
           parameters_digest:str|None=None,approval:dict[str,Any]|None=None,
           consumed:set[str]|None=None)->PolicyDecision:
    consumed=consumed or set()
    incident_open=bool(incident and incident.get("state")=="OPEN")
    incident_high=bool(incident and incident.get("severity") in {"HIGH","CRITICAL"})

    if action=="case_write":
        if incident_open and incident_high and incident.get("principal")==principal:
            return PolicyDecision("DENY","OPEN_HIGH_RISK_INCIDENT",False,False,
                "A identidade está ligada a incidente aberto de alto risco; escrita privilegiada é bloqueada.")
        return PolicyDecision("REQUIRE_HITL","HIGH_RISK_WRITE_REQUIRES_HUMAN",False,True,
            "Escrita de alto risco exige aprovação humana.")

    if action=="export_restricted":
        if approval is None:
            return PolicyDecision("REQUIRE_HITL","HUMAN_APPROVAL_REQUIRED",False,True,
                "Exportação de conteúdo restrito exige aprovação humana vinculada.")
        if principal != approval.get("principal"):
            return PolicyDecision("DENY","IDENTITY_BINDING_MISMATCH",False,False,
                "A identidade atual não corresponde à identidade aprovada.")
        if target != approval.get("target"):
            return PolicyDecision("DENY","PARAMETERS_DIGEST_MISMATCH",False,False,
                "O alvo atual não corresponde ao alvo aprovado.")
        if parameters_digest != approval.get("parameters_digest"):
            return PolicyDecision("DENY","PARAMETERS_DIGEST_MISMATCH",False,False,
                "Os parâmetros atuais não correspondem aos parâmetros aprovados.")
        approval_id=str(approval.get("approval_id",""))
        if approval_id in consumed or approval.get("state")=="CONSUMED":
            return PolicyDecision("DENY","REPLAY_DETECTED",False,False,
                "A aprovação single-use já foi consumida.")
        if approval.get("state")!="APPROVED":
            return PolicyDecision("DENY","APPROVAL_NOT_VALID",False,False,
                "A aprovação não está em estado válido para execução.")
        return PolicyDecision("ALLOW","APPROVAL_VALID",True,False,
            "Identidade, alvo e parâmetros correspondem à aprovação válida e ainda não consumida.")

    return PolicyDecision("DENY","UNKNOWN_ACTION_FAIL_CLOSED",False,False,
        "A ação não possui regra explícita; política fail-closed bloqueia a execução.")
