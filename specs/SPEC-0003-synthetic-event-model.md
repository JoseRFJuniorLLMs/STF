# SPEC-0003 — Modelo Canônico de Evento e Campanha

**Status:** Proposed  
**Prioridade:** P0

## 1. Objetivo

Unificar telemetria da Fase 1 e eventos de controle da Fase 2 sem perder proveniência.

## 2. Envelope

```json
{
  "schema_version":"stf-poc-event/2",
  "event_id":"uuid",
  "campaign_id":"STF-POC-CAMPAIGN-001",
  "incident_id":"STF-POC-INCIDENT-001|null",
  "correlation_id":"uuid",
  "causation_id":"uuid|null",
  "phase":"INTRUSION|POST_COMPROMISE",
  "source":{
    "class":"FIREWALL|WAF|IDENTITY|HOST|NETWORK|DB|APP|AGENT|POLICY",
    "system":"synthetic",
    "adapter_version":"1"
  },
  "actor":{"type":"human|agent|service","id":"synthetic-id"},
  "asset":{"type":"host|account|database|application|case","id":"synthetic-id"},
  "activity":"...",
  "outcome":"...",
  "claimed_time":"RFC3339",
  "payload":{},
  "payload_sha256":"...",
  "labels":["synthetic","poc"]
}
```

## 3. Fase 1

Tipos mínimos:

- network.connection;
- waf.signal;
- identity.login;
- identity.failure;
- host.process;
- host.file;
- network.lateral;
- db.query;
- db.write_attempt;
- app.resource_access;
- security.signal;
- incident.opened;
- incident.updated.

## 4. Fase 2

- agent.tool_requested;
- policy.evaluated;
- approval.requested/granted/rejected/expired;
- app.case_update_requested;
- db.update_requested/executed/denied;
- evidence.exported;
- tamper.detected.

## 5. Canonicalização

JSON canônico versionado. Mesmo `event_id` com bytes diferentes => CONFLICT.

## 6. Proveniência

Todo `SecuritySignal` aponta para raw event(s). Todo incidente aponta para signals. Toda decisão da Fase 2 aponta para incident context quando utilizado.

## 7. Campaign identity

`campaign_id` é criado pelo simulador para a campanha conhecida. Em sistemas reais, correlação não pode presumir de antemão que eventos pertencem à mesma campanha. Por isso, testes também devem usar eventos benignos/estranhos e provar que não são incorporados incorretamente.

## 8. Dados

Todos os identificadores são fictícios. Nenhum processo, usuário, IP interno ou credencial real do STF é usado.
