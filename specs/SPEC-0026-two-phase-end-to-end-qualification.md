# SPEC-0026 — Two-Phase End-to-End Qualification

**Status:** Proposed  
**Prioridade:** P0  
**Dependências:** SPEC-0021..0025 e base transversal

## 1. Objetivo

Provar que as duas fases formam uma campanha única.

## 2. Invariante

```text
FIRST RAW EVENT
 -> SIGNAL
 -> INCIDENT
 -> INCIDENT CONTEXT
 -> PRIVILEGED REQUEST
 -> POLICY DECISION
 -> EFFECT/DENY
 -> TAMPER ATTEMPT
 -> EVIDENCE PACKAGE
```

Cada seta deve ser navegável por referência.

## 3. Gates

### Fase 1

- ingest sources >= 5 classes;
- raw provenance;
- at least one deterministic signal;
- cross-source correlation;
- benign exclusion;
- incident graph;
- incident context.

### Fase 2

- context-aware policy;
- DENY with zero effect;
- HITL valid path;
- replay denied;
- TOCTOU denied;
- tamper detected;
- time travel.

### Evidence

- full campaign manifest;
- object digests;
- graph snapshot;
- policy/approval refs;
- effect refs;
- verifier offline;
- trust limitations.

## 4. Evidence Bundle final

```text
EvidencePackage/
├── manifest.json
├── phase1/
│   ├── raw-events.jsonl
│   ├── security-events.jsonl
│   ├── signals.jsonl
│   └── incident-graph.json
├── phase2/
│   ├── app-audit.jsonl
│   ├── db-audit.jsonl
│   ├── policy.jsonl
│   └── approvals.jsonl
├── proofs/
├── build/
├── qualification/
└── report/
```

## 5. Final scorecard

P0 só passa se ambas as fases e a ligação entre elas passarem.

É proibido declarar sucesso end-to-end se Fase 1 e Fase 2 funcionarem isoladamente mas a provenance entre incidente e policy estiver quebrada.

## 6. Sabotage qualification

Mutation tests devem provar que quebrar:

- signal provenance;
- incident edge;
- incident->policy binding;
- approval binding;
- digest/Merkle;

faz o respectivo gate falhar.
