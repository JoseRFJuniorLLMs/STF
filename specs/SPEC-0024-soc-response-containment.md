# SPEC-0024 — SOC Response & Synthetic Containment

**Status:** Proposed  
**Fase:** 1 / ponte  
**Prioridade:** P0/P1  
**Dependências:** SPEC-0023

## 1. Objetivo

Mostrar que detecção pode gerar resposta governada sem executar ações destrutivas em infraestrutura real.

## 2. Respostas P0

- create alert;
- assign severity;
- mark principal/session as suspected;
- require stronger approval in Phase 2;
- request human acknowledgement;
- generate evidence snapshot.

## 3. Containment sintético

A POC pode simular:

```text
BLOCK_SESSION
ISOLATE_HOST
REVOKE_TOKEN
DENY_PRIVILEGED_ACTION
```

Essas ações operam apenas no cyber range.

## 4. HITL de resposta

Ações potencialmente disruptivas devem poder exigir aprovação humana.

```text
Incident -> Response Proposal -> Approval -> Synthetic Effect
```

## 5. Fail-closed

Se contexto de risco é obrigatório e indisponível para uma ação HIGH, policy não assume “safe”.

## 6. Audit

Registrar:

- incident;
- response;
- requester;
- approver;
- reason;
- effect;
- pre/post state;
- correlation ids.

## 7. Testes

| ID | Teste | Esperado |
|---|---|---|
| SOC-01 | alert on OPEN/HIGH | PASS |
| SOC-02 | compromised principal tag | PASS |
| SOC-03 | containment sem approval quando exigido | DENY |
| SOC-04 | approved synthetic containment | PASS |
| SOC-05 | replay containment approval | DENY |
