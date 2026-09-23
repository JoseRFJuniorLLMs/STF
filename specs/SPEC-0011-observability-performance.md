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
