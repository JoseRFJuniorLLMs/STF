# Plano de Implementação — POC Integrada STF

## Fase 0 — congelar baseline

- fixar commit STF;
- fixar commit HeraclitusDB;
- registrar baseline público do STF;
- gerar BUILD-INFO;
- congelar fixtures e policies.

## Fase 1A — telemetry fabric

Implementar adapters sintéticos:

```text
fw
waf
identity
linux
windows
network
db-audit
application
api
backup
```

Todos convergem para `SecurityEvent`.

Gate:
- schema;
- provenance;
- source_lsn;
- deterministic replay.

## Fase 1B — detecção

Usar Sentinel:

- normalização;
- rules/Sigma subset quando aplicável;
- SecuritySignal;
- threat lookup sintético;
- baseline/anomaly somente se qualificado.

Gate:
- sinal conhecido => DETECTED;
- regra inválida => fail-closed segundo profile;
- replay => mesmos IDs lógicos.

## Fase 1C — correlação e incidente

Construir:

- temporal graph;
- campaign_id;
- entity linking;
- causal chain;
- incident lifecycle.

Gate:
- sinais multi-source viram um incidente;
- evento não relacionado não entra artificialmente na campanha;
- todos os nós apontam para evidence refs.

## Fase 1D — SOC response sintético

Sem tocar rede real:

- alert;
- flag session;
- mark principal compromised;
- simulate containment;
- feed incident context to Phase 2 policy.

## Fase 2A — processo/aplicação fictícia

Criar STF-Digital-like app sintética:

- processo fictício;
- documento fictício;
- classificação fictícia;
- database audit;
- application audit.

## Fase 2B — privileged action control

Integrar Agent Gateway:

- LOW;
- MEDIUM;
- HIGH;
- BLOCKED;
- HITL;
- anti-replay;
- identity binding;
- parameters digest;
- upstream counter.

Policy considera `incident_context`.

## Fase 2C — cover tracks

Sabotagens:

- modify;
- delete;
- reorder;
- truncate;
- bundle tamper;
- approval replay.

## Fase 2D — evidence

Exportar a campanha inteira:

```text
edge signal
 -> incident
 -> compromised principal
 -> privileged request
 -> policy
 -> approval
 -> outcome
 -> tamper attempt
```

Verificar offline.

## Fase 3 — qualification

- CI;
- mutation tests;
- fault injection;
- air-gap kit;
- SBOM;
- scorecard;
- report.

## Ordem crítica

```text
telemetry
 -> detection
 -> correlation
 -> incident
 -> phase2 policy
 -> action
 -> tamper
 -> evidence
```

A ponte `incident -> policy` é o elemento que transforma duas demos em **uma única POC**.
