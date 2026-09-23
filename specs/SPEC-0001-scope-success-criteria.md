# SPEC-0001 — Escopo e Critérios de Sucesso da POC Integrada

**Status:** Proposed  
**Prioridade:** P0

## 1. Objetivo

A POC é uma única campanha com duas fases:

- **Fase 1:** intrusão sintética, ingestão de telemetria, detecção, correlação e incidente.
- **Fase 2:** abuso pós-compromisso, policy enforcement, HITL, tentativa de adulteração e evidência.

Nenhum teste atinge infraestrutura real do STF.

## 2. Frase central

> Detectar e correlacionar uma campanha desde o primeiro ponto de telemetria observável e, após suspeita de comprometimento, impedir ou governar ações críticas e preservar prova verificável do ciclo completo.

## 3. P0 — Fase 1

| ID | Critério | Esperado |
|---|---|---|
| P1-01 | ingest FW/WAF sintético | PASS |
| P1-02 | ingest Identity | PASS |
| P1-03 | ingest host Linux/Windows | PASS |
| P1-04 | ingest DB audit | PASS |
| P1-05 | ingest App audit | PASS |
| P1-06 | provenance até raw source | PASS |
| P1-07 | rule detection | DETECTED |
| P1-08 | cross-source correlation | PASS |
| P1-09 | incident graph | PASS |
| P1-10 | unrelated event exclusion | PASS |
| P1-11 | incident context export | PASS |

## 4. P0 — Fase 2

| ID | Critério | Esperado |
|---|---|---|
| P2-01 | restricted read policy | ALLOW/DENY conforme profile |
| P2-02 | write sem approval | DENY |
| P2-03 | write com HITL válido | PASS |
| P2-04 | replay approval | DENY |
| P2-05 | identity swap | DENY |
| P2-06 | parameter swap | DENY |
| P2-07 | DENY alcança upstream | upstream_delta=0 |
| P2-08 | delete history | DETECTED |
| P2-09 | modify history | DETECTED |
| P2-10 | reorder | DETECTED |
| P2-11 | time travel | PASS |
| P2-12 | offline evidence | PASS |

## 5. Gate end-to-end

```text
first_signal.campaign_id
 ==
incident.campaign_id
 ==
privileged_request.campaign_id
 ==
evidence_package.campaign_id
```

A cadeia deve ser navegável nos dois sentidos.

## 6. Status canônicos

`PASS FAIL DENY DETECTED REJECT UNKNOWN PARTIAL UNVERIFIED NOT_CONFIGURED NOT_APPLICABLE`.

## 7. Limites

Não provar:

- que qualquer invasão será detectada;
- que o STF usa os mesmos produtos sintéticos;
- prevenção absoluta;
- integração real;
- certificação;
- conformidade institucional automática.

## 8. DoD

A POC só termina quando uma execução limpa reproduz as duas fases, os testes negativos ficam verdes por observar o resultado negativo correto e o verifier valida o pacote final com a origem desligada.
