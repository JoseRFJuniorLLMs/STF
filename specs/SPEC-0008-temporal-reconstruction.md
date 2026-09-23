# SPEC-0008 — Reconstrução Temporal e Estado Histórico

**Status:** Proposed  
**Classe:** Temporal Data / Audit  
**Prioridade:** P0  
**Dependências:** SPEC-0003, SPEC-0004

## 1. Objetivo

Demonstrar que o sistema responde não apenas “qual é o estado atual?”, mas também “qual era o estado naquele ponto da história?”.

## 2. Modelo

Estado é derivado dos eventos.

Exemplo:

```text
LSN 100 document.created       classification=INTERNAL
LSN 101 document.read
LSN 102 classification_changed classification=RESTRICTED
LSN 103 approval.requested
LSN 104 approval.granted
LSN 105 export.executed
```

Consultas obrigatórias:

- state_at(101) => INTERNAL;
- state_at(103) => RESTRICTED e export ainda não executado;
- state_at(105) => export executado.

## 3. Identificadores temporais

A POC deve preferir LSN como referência determinística.

HLC pode ser exibido como dimensão temporal adicional.

Tempo de parede deve ser tratado como `claimed_time`, salvo quando ancorado externamente por mecanismo confiável.

## 4. Invariantes

- reconstrução não pode consultar apenas o estado atual;
- evento futuro não pode afetar state_at anterior;
- reprocessamento do mesmo intervalo deve produzir estado lógico equivalente;
- lacuna detectada no histórico deve impedir resposta “completa” silenciosa.

## 5. Cenário de demonstração

Pergunta:

```text
Como estava DOC-0001 antes da aprovação?
```

Resposta esperada:

```text
classification: RESTRICTED
approval: PENDING
export: NOT_EXECUTED
as_of_lsn: 103
```

Depois:

```text
Como estava DOC-0001 após a aprovação e antes da execução?
```

A saída deve diferenciar claramente autorização de efeito executado.

## 6. Testes negativos

- solicitar LSN inexistente => ERROR/UNKNOWN;
- histórico adulterado => reconstrução não pode ser apresentada como confiável;
- intervalo incompleto => PARTIAL com razão;
- evento com schema incompatível => falha explícita ou migração versionada.

## 7. Evidência

Cada resposta de time-travel na demo deve registrar:

- query;
- as_of_lsn;
- input range;
- state digest;
- build identity.

Isso permite relacionar a consulta ao bundle final.
