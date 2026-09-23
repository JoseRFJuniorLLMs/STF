# SPEC-0025 — Post-Compromise Process & Data Abuse

**Status:** Proposed  
**Fase:** 2 — Pós-compromisso  
**Prioridade:** P0  
**Dependências:** SPEC-0023, SPEC-0024, SPEC-0005

## 1. Objetivo

Continuar a campanha da Fase 1 usando a mesma identidade/contexto e demonstrar tentativa de abuso sobre aplicação judicial fictícia e banco sintético.

## 2. Aplicação

Nome interno da POC:

`JusticeCaseLab`.

Ela representa apenas conceitos genéricos de um sistema judicial eletrônico:

- case;
- docket/event;
- metadata;
- document;
- classification;
- actor;
- audit trail.

Não reproduz API ou schema do STF.

## 3. Caso fictício

```text
case://SYNTHETIC/RE-000001
status=ACTIVE
classification=RESTRICTED
relator=SYNTHETIC
```

## 4. Tentativas

A identidade marcada na Fase 1 tenta:

- read restricted metadata;
- list documents;
- change metadata;
- attach synthetic document;
- change classification;
- export document;
- delete audit record;
- invoke privileged AI/tool action.

## 5. Context-aware policy

Exemplo:

```text
IF incident.state == OPEN
AND incident.severity == HIGH
AND principal is linked
AND action.risk == HIGH
THEN DENY or REQUIRE_STRONG_APPROVAL
```

O profile da demo define qual ação é DENY absoluto e qual permite HITL.

## 6. Banco

O banco da POC é engine-neutral.

Gerar audit events para:

- SELECT;
- UPDATE requested;
- UPDATE denied/executed;
- DELETE attempt.

Não presumir banco transacional atual do STF.

## 7. Oráculo

Para qualquer DENY:

`upstream_delta == 0`.

Para ALLOW autorizado:

`upstream_delta == 1` e effect digest registrado.

## 8. Encobrimento

Após uma operação controlada, o atacante tenta:

- apagar audit event;
- modificar decisão;
- trocar ordem;
- adulterar export.

Esperado: DETECTED/FAIL.

## 9. Testes

P2-WRITE-01..P2-WRITE-10 devem cobrir incidente-context, HITL, replay, identity swap, parameter swap, effect counter e tamper.
