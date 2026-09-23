# SPEC-0002 — Arquitetura Integrada de Referência

**Status:** Proposed  
**Prioridade:** P0

## 1. Arquitetura

```text
                         CYBER RANGE ISOLADO
                               |
                +--------------+--------------+
                |                             |
                v                             v
         Attack Simulator              Benign Traffic
                |                             |
                +--------------+--------------+
                               |
          +--------------------+--------------------+
          |         |          |         |          |
         FW        IAM        HOST      DB        APP
          |         |          |         |          |
          +--------------------+--------------------+
                               |
                               v
                         TELEMETRY ADAPTERS
                               |
                               v
                         HERACLITUS HRKL
                               |
                               v
                            SENTINEL
                    normalize / detect / graph
                               |
                               v
                         INCIDENT CONTEXT
                               |
                               v
                  +------------+------------+
                  |                         |
                  v                         v
          SOC alert/response         PHASE 2 POLICY
                                            |
                                            v
                                 Synthetic Judicial App
                                            |
                                      Agent Gateway
                                            |
                                 Policy / Approval / HITL
                                            |
                                            v
                                     Synthetic DB
                                            |
                                            v
                                      HRKL Evidence
                                            |
                                            v
                                  OFFLINE VERIFIER
```

## 2. Zonas

A — telemetry producers  
B — normalization/persistence  
C — detection/correlation  
D — incident context  
E — application/agent enforcement  
F — evidence/export  
G — independent verifier

## 3. Princípio de observabilidade

Heraclitus só pode detectar o que recebe.

```text
NO TELEMETRY
   =>
NO CLAIM OF DETECTION
```

## 4. Princípio de enforcement

Heraclitus/Gateway só pode impedir efeito quando a rota do efeito atravessa um ponto governado.

```text
DIRECT CREDENTIAL + DIRECT ROUTE
   =>
GATEWAY CANNOT GUARANTEE BLOCK
```

A POC remove essa rota por construção.

## 5. Ponte Fase 1 -> Fase 2

`IncidentContext` mínimo:

- incident_id;
- campaign_id;
- principals;
- hosts;
- resources;
- severity;
- confidence;
- evidence_refs;
- state OPEN/CLOSED;
- detected_at;
- policy_tags.

A policy da Fase 2 pode consultar esse contexto.

## 6. Infra aproximada

A arquitetura usa classes publicamente documentadas no STF, mas vendors sensíveis ou não confirmados permanecem adapters genéricos.

## 7. Failure domains

Falhas de Sentinel não podem corromper HRKL; falha de policy em ação HIGH deve negar; falha do upstream resulta FAILED/UNKNOWN; falha do exporter não altera história; verifier não possui rota de escrita à origem.
