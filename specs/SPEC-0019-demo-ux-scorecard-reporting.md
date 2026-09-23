# SPEC-0019 — UX da Demonstração, Scorecard e Relatório Técnico

**Status:** Proposed  
**Classe:** Demo UX / Reporting  
**Prioridade:** P0  
**Dependências:** SPEC-0010, SPEC-0011

## 1. Objetivo

Fazer a equipe técnica entender o estado sem depender de narração.

## 2. Tela principal

Mostrar run_id, commits, gateway mode, policy version, event count, Merkle root, pending approvals, upstream hit count e qualification status.

## 3. Estados visuais

Os textos são autoritativos. Cor é auxiliar:

- PASS;
- DENY_EXPECTED;
- DETECTED;
- FAIL;
- UNKNOWN;
- NOT_CONFIGURED;
- UNVERIFIED.

Nunca depender apenas de verde/vermelho.

## 4. Drill-down

Cada linha aponta para test_id, comando, expected, observed, reason code, evidence refs e logs relevantes.

## 5. Relatório

JSON é autoritativo. HTML/PDF são apresentações derivadas. Em divergência, prevalece o JSON estruturado.

## 6. Limitações visíveis

```text
REAL STF DATA             NOT USED
REAL STF IAM              NOT CONFIGURED
INSTITUTIONAL HSM         NOT CONFIGURED
ICP-BRASIL TRUST          UNVERIFIED
PJE INTEGRATION           NOT TESTED
PRODUCTION HA/DR          NOT TESTED
```

## 7. Export

O relatório final entra no Evidence Bundle por digest.
