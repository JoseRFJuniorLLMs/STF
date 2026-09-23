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


---

## 8. Reducers versionados

A reconstrução usa reducer explicitamente versionado:

```text
event schema v1 + reducer v1 -> state digest X
```

Mudança de regra não altera silenciosamente resultados históricos.

## 9. Determinismo

Reexecutar o mesmo intervalo após restart, em processo novo e, quando possível, a partir do bundle. O state digest lógico deve permanecer igual.

## 10. Lacunas e forks

LSN faltante, evento incompatível duplicado, proof inválida ou intervalo truncado resultam em `completeness=PARTIAL/INVALID`.

## 11. Resposta as-of

```json
{
  "resource_id":"DOC-0001",
  "as_of_lsn":103,
  "state":{},
  "state_digest":"...",
  "history_root":"...",
  "completeness":"COMPLETE",
  "reducer_version":"1"
}
```

## 12. Causalidade

Exibir quando disponível:

```text
tool_requested
 -> policy_evaluated
 -> approval_requested
 -> approval_granted
 -> tool_executed
```

## 13. Semântica temporal

LSN é a ordem canônica dentro do escopo testado. HLC auxilia ordenação temporal. `claimed_time` é dado de origem e não prova tempo confiável sem ancoragem externa.
