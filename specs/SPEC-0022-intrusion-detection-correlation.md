# SPEC-0022 — Intrusion Detection & Cross-Source Correlation

**Status:** Proposed  
**Fase:** 1 — Invasão  
**Prioridade:** P0  
**Dependências:** SPEC-0021

## 1. Objetivo

Transformar eventos heterogêneos em sinais e correlacioná-los sem afirmar que qualquer evento incomum é necessariamente invasão.

## 2. Camadas

```text
L0 normalization
L1 deterministic rules / Sigma subset
L2 behavioral/anomaly where qualified
L3 temporal/entity correlation
L4 investigation context
```

A POC usa apenas camadas que estejam implementadas e qualificadas no baseline fixado.

## 3. Detecções P0

Exemplos seguros e sintéticos:

- autenticação em contexto novo;
- sequência de falhas seguida de sucesso;
- processo incomum em host de laboratório;
- conexão lateral sintética;
- consulta de DB fora do perfil do ator fictício;
- acesso a recurso restrito após mudança de contexto.

Não é necessário implementar exploração real para produzir esses sinais.

## 4. SecuritySignal

Campos mínimos:

- signal_id;
- source_event_refs;
- detector_id;
- detector_version;
- rule_id;
- severity;
- confidence;
- entities;
- reason_code;
- generated_at;
- source_lsn refs.

## 5. Correlação

Entidades possíveis:

- principal;
- session;
- host;
- source endpoint sintético;
- destination;
- application;
- database;
- resource/case;
- campaign candidate.

A correlação deve exigir evidência suficiente e permitir `UNCONFIRMED`.

## 6. Negative correlation

A fixture inclui eventos benignos temporalmente próximos.

Critério: o sistema não pode adicionar todo evento “estranho” à campanha apenas porque aconteceu na mesma janela.

## 7. Determinismo

Replay do mesmo histórico + mesmas rules => mesmos IDs lógicos de signals/correlações, salvo campos explicitamente não determinísticos.

## 8. Testes

| ID | Caso | Esperado |
|---|---|---|
| DET-01 | rule conhecida | DETECTED |
| DET-02 | evento benigno | NO_SIGNAL |
| DET-03 | rule inválida | fail-closed/profile |
| CORR-01 | sinais relacionados | SAME_INCIDENT |
| CORR-02 | sinal não relacionado | EXCLUDED |
| CORR-03 | replay | same logical result |
| CORR-04 | source event ausente | PARTIAL/INVALID |
