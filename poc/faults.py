"""Deterministic resilience/fault-injection scenarios for STF POC."""
from __future__ import annotations
from typing import Any

KINDS=("policy_store_down","timeout_before_effect","timeout_after_effect","exporter_interrupted","clock_jump")

def simulate(kind:str)->dict[str,Any]:
    if kind=="policy_store_down":
        return {
            "kind":kind,"initial_state":"POLICY_UNAVAILABLE","decision":"DENY","upstream_delta":0,
            "final_state":"FAIL_CLOSED","reconciliation":"NOT_REQUIRED","status":"PASS",
            "explanation":"Ação HIGH não assume estado seguro quando a policy está indisponível."
        }
    if kind=="timeout_before_effect":
        return {
            "kind":kind,"initial_state":"UNKNOWN","decision":"UNKNOWN","upstream_delta":0,
            "final_state":"RESOLVED_NOT_EXECUTED","reconciliation":"UPSTREAM_ORACLE_ZERO","status":"PASS",
            "explanation":"Timeout ocorreu antes do efeito; reconciliação confirma que nada chegou ao serviço protegido."
        }
    if kind=="timeout_after_effect":
        return {
            "kind":kind,"initial_state":"UNKNOWN","decision":"UNKNOWN","upstream_delta":1,
            "final_state":"RESOLVED_EXECUTED","reconciliation":"UPSTREAM_ORACLE_ONE","status":"PASS",
            "explanation":"Timeout ocorreu depois do efeito; o sistema não inventa sucesso, marca UNKNOWN e reconcilia pelo oráculo independente."
        }
    if kind=="exporter_interrupted":
        return {
            "kind":kind,"initial_state":"EXPORT_INTERRUPTED","decision":"RETRY","upstream_delta":None,
            "final_state":"HISTORY_UNCHANGED","reconciliation":"REEXPORT_FROM_CANONICAL_HISTORY","status":"PASS",
            "explanation":"Falha do exporter não altera a história canônica; nova exportação parte da mesma evidência."
        }
    if kind=="clock_jump":
        return {
            "kind":kind,"initial_state":"SOURCE_TIME_REGRESSED","decision":"PRESERVE","upstream_delta":None,
            "final_state":"ORDER_PRESERVED_BY_LSN_HLC","reconciliation":"CLAIMED_TIME_FLAGGED","status":"PASS",
            "explanation":"Relógio da fonte pode regredir sem reordenar a história canônica baseada em LSN/HLC."
        }
    return {"kind":kind,"status":"REJECT","error":"unsupported fault kind","supported":list(KINDS)}
