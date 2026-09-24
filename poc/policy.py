"""Fail-closed policy engine for the synthetic STF POC."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from typing import Any
import time

@dataclass(frozen=True)
class PolicyDecision:
    outcome:str
    reason_code:str
    effect_allowed:bool
    requires_human:bool
    explanation:str
    def to_dict(self): return asdict(self)

def _validate_approval(*,principal:str,target:str,parameters_digest:str|None,
                       approval:dict[str,Any]|None,consumed:set[str],now:float)->PolicyDecision|None:
    if approval is None:
        return PolicyDecision("REQUIRE_HITL","HUMAN_APPROVAL_REQUIRED",False,True,
            "Ação sensível exige aprovação humana vinculada.")
    if principal != approval.get("principal"):
        return PolicyDecision("DENY","IDENTITY_BINDING_MISMATCH",False,False,
            "A identidade atual não corresponde à identidade aprovada.")
    if target != approval.get("target"):
        return PolicyDecision("DENY","PARAMETERS_DIGEST_MISMATCH",False,False,
            "O alvo atual não corresponde ao alvo aprovado.")
    if parameters_digest != approval.get("parameters_digest"):
        return PolicyDecision("DENY","PARAMETERS_DIGEST_MISMATCH",False,False,
            "Os parâmetros atuais não correspondem aos parâmetros aprovados.")
    expiry=approval.get("expires_at_epoch")
    if isinstance(expiry,(int,float)) and now>float(expiry):
        return PolicyDecision("DENY","APPROVAL_EXPIRED",False,False,
            "A aprovação expirou antes da tentativa de execução.")
    approval_id=str(approval.get("approval_id",""))
    if approval_id in consumed or approval.get("state")=="CONSUMED":
        return PolicyDecision("DENY","REPLAY_DETECTED",False,False,
            "A aprovação single-use já foi consumida.")
    if approval.get("state")=="PENDING":
        return PolicyDecision("REQUIRE_HITL","APPROVAL_PENDING",False,True,
            "A aprovação já foi criada e ainda aguarda decisão humana.")
    if approval.get("state")!="APPROVED":
        return PolicyDecision("DENY","APPROVAL_NOT_VALID",False,False,
            "A aprovação não está em estado válido para execução.")
    return None

def decide(*,action:str,incident:dict[str,Any]|None,principal:str,target:str,
           parameters_digest:str|None=None,approval:dict[str,Any]|None=None,
           consumed:set[str]|None=None,now:float|None=None)->PolicyDecision:
    consumed=consumed or set()
    now=time.time() if now is None else now
    incident_open=bool(incident and incident.get("state")=="OPEN")
    incident_high=bool(incident and incident.get("severity") in {"HIGH","CRITICAL"})

    if action=="case_write":
        if incident_open and incident_high and incident.get("principal")==principal:
            return PolicyDecision("DENY","OPEN_HIGH_RISK_INCIDENT",False,False,
                "A identidade está ligada a incidente aberto de alto risco; escrita privilegiada é bloqueada.")
        approval_result=_validate_approval(
            principal=principal,target=target,parameters_digest=parameters_digest,
            approval=approval,consumed=consumed,now=now,
        )
        if approval_result is not None:
            if approval_result.reason_code=="HUMAN_APPROVAL_REQUIRED":
                return PolicyDecision("REQUIRE_HITL","HIGH_RISK_WRITE_REQUIRES_HUMAN",False,True,
                    "Escrita de alto risco exige aprovação humana.")
            return approval_result
        return PolicyDecision("ALLOW","APPROVAL_VALID",True,False,
            "A escrita corresponde a uma aprovação humana válida, vinculada e ainda não consumida.")

    if action=="export_restricted":
        approval_result=_validate_approval(
            principal=principal,target=target,parameters_digest=parameters_digest,
            approval=approval,consumed=consumed,now=now,
        )
        if approval_result is not None:
            return approval_result
        return PolicyDecision("ALLOW","APPROVAL_VALID",True,False,
            "Identidade, alvo e parâmetros correspondem à aprovação válida e ainda não consumida.")

    return PolicyDecision("DENY","UNKNOWN_ACTION_FAIL_CLOSED",False,False,
        "A ação não possui regra explícita; política fail-closed bloqueia a execução.")
