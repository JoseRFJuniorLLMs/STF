# SPEC-0023 — Attack Graph & Incident Lifecycle

**Status:** Proposed  
**Fase:** 1 / ponte  
**Prioridade:** P0  
**Dependências:** SPEC-0022

## 1. Objetivo

Representar a campanha como grafo temporal auditável e converter um conjunto de sinais em incidente sem destruir provenance.

## 2. Nós

- Event;
- Signal;
- Principal;
- Session;
- Host;
- Application;
- Database;
- Resource;
- Incident;
- PolicyDecision;
- Approval;
- Effect.

## 3. Arestas

```text
DERIVED_FROM
OBSERVED_ON
AUTHENTICATED_AS
CONNECTED_TO
ACCESSED
CAUSED
CORRELATED_WITH
PART_OF_INCIDENT
REQUESTED
AUTHORIZED_BY
EXECUTED
TAMPERED
```

## 4. Lifecycle

```text
CANDIDATE
 -> OPEN
 -> CONTAINMENT_RECOMMENDED
 -> MONITORING
 -> CLOSED

ou

CANDIDATE -> DISMISSED
```

A POC não fecha incidente automaticamente só porque a demo terminou.

## 5. Provenance

Cada edge analítica deve poder retornar às evidências de origem.

Pergunta de auditoria:

> Por que este principal foi marcado como relacionado a este incidente?

Resposta deve apontar para signals e raw events.

## 6. Confidence

Confidence não é probabilidade matemática de invasão salvo se houver modelo calibrado para isso.

Usar níveis ou score documentado:

`LOW MEDIUM HIGH` ou score técnico com semântica explicitada.

## 7. Ponte para Fase 2

Quando incidente OPEN/HIGH envolve `principal:service-account-17`, publicar `IncidentContext` para policy.

Isso não revoga automaticamente credenciais reais; na POC apenas altera comportamento do enforcement sintético.

## 8. Testes

- graph contains all causal refs;
- benign event excluded;
- missing raw ref => invalid edge;
- principal risk context exported;
- incident survives restart/replay;
- graph snapshot deterministic enough for comparison.
