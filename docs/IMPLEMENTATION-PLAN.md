# Plano de Implementação — POC STF HeraclitusDB

## Objetivo

Transformar as 20 SPECs em uma POC executável sem tentar implementar tudo ao mesmo tempo.

## Fase 0 — congelar baseline

Entregáveis:

- commit STF fixado;
- commit HeraclitusDB fixado;
- BUILD-INFO inicial;
- toolchain fixada;
- fixtures iniciais.

Gate: nenhum desenvolvimento começa com dependência apontando para branch flutuante.

## Fase 1 — vertical slice de integridade

Implementar:

1. `poc up`;
2. `poc seed`;
3. ingestão de eventos sintéticos;
4. captura LSN/HLC;
5. checkpoint/seal necessário;
6. root/proof;
7. `poc integrity-test`;
8. sabotagem modify/delete/reorder.

Saída: AC-01..04 verdes.

## Fase 2 — time travel

Implementar reducer v1, state digest e `state_at(lsn)`.

Saída: AC-05 e AC-16.

## Fase 3 — Agent Gateway

Integrar gateway existente do HeraclitusDB.

Implementar ferramentas sintéticas LOW/MEDIUM/HIGH/BLOCKED, upstream counter e approval UI/CLI.

Saída: AC-06..10, AC-17..20.

## Fase 4 — red team

Ligar runner/campanha existente aos cenários da SPEC-0006.

Prioridade:

- replay;
- concurrent double-spend;
- identity swap;
- parameter substitution;
- invalid policy reload;
- flood DENY;
- oversized identity;
- bypass.

Saída: upstream_delta como oráculo independente.

## Fase 5 — Evidence Bundle v1

Implementar exporter POC e verifier separado.

Ordem do verifier conforme SPEC-0007, incluindo path validation e resource bounds.

Saída: AC-11..13, AC-21/22/28/29.

## Fase 6 — air-gap kit

Gerar:

- binários;
- imagens;
- hashes;
- fixtures;
- policies;
- SBOM;
- BUILD-INFO;
- RUNBOOK.

Executar verifier sem egress.

Saída: AC-15, AC-25, AC-26.

## Fase 7 — fault injection

Crash, disk full, timeout, exporter parcial, policy store down e restart.

Saída: AC-24 + SPEC-0017.

## Fase 8 — qualification

CI executa todos P0, negative assertions e mutation tests.

Gerar qualification-summary.json.

## Fase 9 — UX da reunião

Construir scorecard local sobre dados estruturados existentes. A UI não cria status; apenas renderiza resultados.

## Estrutura alvo

```text
STF/
├── README.md
├── specs/
├── docs/
├── fixtures/
├── policies/
├── poc/
│   ├── cli/
│   ├── adapter/
│   ├── producer/
│   ├── upstream/
│   ├── exporter/
│   └── verifier/
├── tests/
│   ├── integration/
│   ├── adversarial/
│   ├── mutation/
│   └── fault/
├── deploy/
├── scripts/
└── .github/workflows/
```

## Ordem de prioridade

```text
integrity
  -> verifier
  -> agent/HITL
  -> red team
  -> air-gap
  -> fault injection
  -> UX
```

Primeiro provar. Depois embelezar.
