# SPEC-0018 — Contratos de Integração, APIs e Adapters

**Status:** Proposed  
**Classe:** Integration / API Contract  
**Prioridade:** P1  
**Dependências:** SPEC-0002, SPEC-0003

## 1. Objetivo

Manter o core independente de PJe, SEI, SIEM ou qualquer produto específico.

## 2. Adapter contract

Entrada mínima: source system, source event id, actor, resource, action, claimed time, payload e schema version.

Saída mínima: accepted/rejected, canonical event id, LSN quando persistido, correlation id e reason code.

## 3. Idempotência

Mesma idempotency_key + mesmo digest => resultado existente.

Mesma idempotency_key + digest diferente => CONFLICT.

## 4. Error envelope

```json
{
  "error":{
    "code":"POLICY_DENY",
    "message":"human-readable",
    "correlation_id":"...",
    "retryable":false
  }
}
```

Mensagens não vazam secrets.

## 5. Versioning

APIs e schemas possuem versão explícita. Breaking change sem nova versão é proibido.

## 6. MCP/tool contract

Registrar tool name normalizado, arguments canonicalizados, arguments digest, principal, target, policy context, approval ref e result digest.

## 7. Integração institucional futura

Adapters reais são componentes isolados, testados contra sandbox/fixtures e sem credencial ou semântica específica incorporada ao core Heraclitus.
