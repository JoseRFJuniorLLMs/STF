# SPEC-0011 — Observabilidade e Desempenho da POC

**Status:** Proposed  
**Classe:** Observability / Performance  
**Prioridade:** P1  
**Dependências:** SPEC-0002

## 1. Objetivo

Medir o custo técnico da camada de confiança sem transformar uma POC funcional em benchmark publicitário.

## 2. Métricas mínimas

Coletar:

- eventos ingeridos;
- eventos rejeitados;
- bytes ingeridos;
- latência p50/p95/p99 de append;
- latência de policy evaluation;
- latência de aprovação excluindo tempo humano;
- tempo de exportação;
- tempo de verificação offline;
- tamanho do Evidence Bundle;
- CPU/memória aproximadas;
- falhas de persistência;
- contagem de DENY por motivo.

## 3. Correlação

Toda operação relevante deve compartilhar correlation_id entre:

- request;
- policy;
- approval;
- execution;
- evidence.

## 4. Segurança dos logs

Logs não podem conter:

- secrets;
- tokens completos;
- chaves privadas;
- conteúdo classificado real;
- dados pessoais reais.

Como a POC usa dados sintéticos, qualquer ocorrência desses itens é bug.

## 5. Benchmark

O relatório deve declarar:

- hardware;
- SO;
- runtime/container;
- commit;
- dataset;
- duração;
- warm/cold;
- número de repetições.

Uma única execução não pode ser apresentada como capacidade sustentada de produção.

## 6. Thresholds POC

Os thresholds iniciais são operacionais, não SLA:

- nenhuma etapa interativa pode travar indefinidamente;
- cada comando deve possuir timeout;
- export e verify devem produzir progresso/status;
- consumo de memória deve permanecer limitado pelo dataset de POC.

Valores numéricos definitivos serão fixados após primeira baseline.

## 7. Relatório

Gerar:

```json
{
  "run_id": "...",
  "commit": "...",
  "environment": {},
  "metrics": {},
  "test_results": {},
  "limitations": []
}
```

## 8. Falhas

Métrica ausente deve aparecer como NOT_COLLECTED, não zero.


---

## 9. Telemetria versus evidência

Classificar registros:

```text
OPERATIONAL
SECURITY_AUDIT
SECURITY_EVIDENCE
DEMO_RESULT
```

Telemetria operacional pode ser descartável. Evidência canônica não.

## 10. Métricas do gateway

Quando disponíveis:

- requests total;
- allow/deny total;
- require approval;
- replay rejected;
- approvals pending;
- approval latency;
- upstream hits;
- red-team events.

## 11. Cardinalidade

`correlation_id`, `event_id` e `approval_id` pertencem a logs/evidência, evitando labels de alta cardinalidade sem necessidade.

## 12. Tracing

Trace pode correlacionar producer/gateway/upstream, mas não substitui audit event. Sampling não pode remover SECURITY_EVIDENCE.

## 13. Perfis

Manter:

1. correctness: todos os checks;
2. demo-load: carga moderada repetível.

Nunca desligar integridade para produzir benchmark mais bonito.

## 14. Regressão

A primeira execução qualificada cria baseline. Mudanças relevantes de latência, memória ou tamanho do bundle são sinalizadas como regressão potencial, não automaticamente como falha funcional.
