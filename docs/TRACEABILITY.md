# Matriz de Rastreabilidade — POC Integrada

## Fase 1

| Claim | SPEC | Teste | Evidência |
|---|---|---|---|
| fontes heterogêneas normalizam | 0021 | P1-INGEST-* | SecurityEvent + source refs |
| regra produz sinal | 0022 | P1-DETECT-01 | SecuritySignal |
| múltiplos sinais correlacionam | 0022/0023 | P1-CORR-01 | graph edges |
| evento inocente não contamina campanha | 0023 | P1-CORR-NEG | graph absence |
| incidente preserva provenance | 0023 | P1-PROV-01 | LSN/evidence refs |
| contexto do incidente chega à policy | 0024/0025 | BRIDGE-01 | policy decision |

## Fase 2

| Claim | SPEC | Teste | Evidência |
|---|---|---|---|
| principal comprometido não altera processo sem gate | 0025 | P2-WRITE-01 | DENY + upstream_delta=0 |
| HITL válido permite cenário autorizado | 0005/0025 | P2-HITL-01 | approval + effect |
| replay é bloqueado | 0006 | P2-REPLAY | DENY + upstream_delta=0 |
| parameter swap é bloqueado | 0005 | P2-TOCTOU | digest mismatch |
| história detecta alteração | 0004 | INT-* | Merkle/digest |
| bundle verifica offline | 0007 | EVID-* | verifier output |

## End-to-end

| Claim | SPEC | Evidência |
|---|---|---|
| mesma campanha atravessa as fases | 0026 | campaign_id/incident_id |
| primeiro sinal liga ao abuso final | 0023/0026 | causal graph |
| bundle contém a linha do tempo completa | 0007/0026 | manifest + refs |
| limitações ficam explícitas | 0001/0027 | qualification summary |

Nenhuma claim entra na apresentação sem teste e evidência.
