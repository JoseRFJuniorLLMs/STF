# SPEC-0010 — Runbook Integrado da Demonstração

**Status:** Proposed  
**Prioridade:** P0

## 1. Duração alvo

40–50 minutos.

## 2. Preflight

- commits fixados;
- hashes;
- network isolation;
- upstream counter = 0;
- Sentinel ready;
- policies loaded;
- fixtures;
- offline verifier;
- run_id novo.

## 3. Ato 1 — primeira telemetria

Mostrar fluxo benigno por alguns segundos.

Depois iniciar campanha:

```text
./poc campaign start STF-POC-CAMPAIGN-001
```

Exibir eventos chegando de fontes diferentes sem afirmar ainda “invasão confirmada”.

## 4. Ato 2 — detecção

Uma regra/sinal é acionada.

Mostrar:

- raw event;
- source LSN;
- SecuritySignal;
- rule/reason;
- evidence ref.

## 5. Ato 3 — correlação

Novos eventos de identity, host, DB e app formam o grafo.

Mostrar um evento benigno próximo que **não** entra no incidente.

Abrir:

`STF-POC-INCIDENT-001`.

## 6. Ato 4 — comprometimento suspeito

Marcar contexto:

```text
principal=service-account-17
incident=OPEN
severity=HIGH
policy_tag=COMPROMISE_SUSPECTED
```

Nenhuma conta real.

## 7. Ato 5 — atacante tenta alterar processo fictício

```text
case://SYNTHETIC/RE-000001
action=change_metadata
```

Sem approval:

`DENY + upstream_delta=0`.

## 8. Ato 6 — HITL

Nova operação explicitamente autorizável.

Mostrar approval binding e permitir execução única.

Depois replay:

`DENY + upstream_delta=0`.

## 9. Ato 7 — parameter/identity swap

Alterar argumento ou identidade após aprovação.

Esperado: DENY.

## 10. Ato 8 — apagar rastros

Executar sabotagens controladas em cópia/lab:

- modify;
- delete;
- reorder.

Esperado: DETECTED.

## 11. Ato 9 — timeline

Consultar:

- estado antes da intrusão;
- após incidente;
- antes da tentativa de write;
- após operação permitida.

## 12. Ato 10 — evidence

Exportar pacote completo.

Parar origem/retirar egress.

Verificar offline.

## 13. Tela final

Mostrar Fase 1, Fase 2 e limitações separadamente. Nenhum `UNVERIFIED` pode ser ocultado.

## 14. Regra

Não executar exploit real nem apontar scanner para domínio/IP do STF. A “invasão” é uma campanha sintética em ambiente isolado que gera telemetria equivalente para testar defesa.
