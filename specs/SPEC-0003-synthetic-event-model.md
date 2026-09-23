# SPEC-0003 — Modelo Canônico de Eventos Sintéticos

**Status:** Proposed  
**Classe:** Data Model / Provenance  
**Prioridade:** P0  
**Dependências:** SPEC-0002

## 1. Objetivo

Definir eventos sintéticos suficientes para provar integridade, proveniência, decisão de política, aprovação humana e reconstrução temporal sem usar qualquer dado real do STF.

## 2. Envelope canônico

Todo evento deve possuir:

```json
{
  "schema_version": "stf-poc-event/1",
  "event_id": "uuid",
  "correlation_id": "uuid",
  "event_type": "action.requested",
  "actor": {
    "type": "human|agent|service",
    "id": "synthetic-id"
  },
  "resource": {
    "type": "synthetic-document",
    "id": "DOC-0001",
    "classification": "PUBLIC|INTERNAL|RESTRICTED"
  },
  "claimed_time": "RFC3339",
  "payload": {},
  "payload_sha256": "hex",
  "labels": ["synthetic", "poc"]
}
```

## 3. Eventos mínimos

A POC deve suportar:

- identity.authenticated;
- document.created;
- document.read;
- document.classification_changed;
- agent.tool_requested;
- policy.evaluated;
- approval.requested;
- approval.granted;
- approval.rejected;
- approval.expired;
- tool.executed;
- tool.denied;
- evidence.export_requested;
- evidence.export_completed.

## 4. Cenário base

Documento sintético:

```text
DOC-0001
classificação inicial: INTERNAL
conteúdo: "CONTEUDO SINTETICO STF POC 0001"
```

Atores:

```text
human:analyst-01
human:approver-01
agent:research-01
service:demo-upstream
```

## 5. Regras

- IDs não podem conter nome, CPF, matrícula ou outro identificador real.
- Conteúdo sintético deve ser claramente marcado.
- Um evento nunca pode sobrescrever outro evento.
- Alterações de estado geram novos eventos.
- O estado corrente é derivado da sequência histórica.

## 6. Estado derivado

Exemplo:

```text
LSN 10 document.created INTERNAL
LSN 11 document.read
LSN 12 classification_changed RESTRICTED
LSN 13 agent.tool_requested
```

Consulta no LSN 11 deve retornar INTERNAL.

Consulta no LSN 13 deve retornar RESTRICTED.

## 7. Digest

O payload deve possuir SHA-256 para interoperabilidade da POC. Se a infraestrutura subjacente usar BLAKE3/Merkle, ambos podem coexistir.

Nenhum digest substitui outro implicitamente.

## 8. Dataset determinístico

O repositório deverá futuramente conter fixtures versionadas:

```text
fixtures/
├── scenario-happy-path.jsonl
├── scenario-tamper.jsonl
├── scenario-agent-deny.jsonl
└── scenario-replay.jsonl
```

A mesma seed deve produzir os mesmos eventos lógicos, exceto campos explicitamente variáveis e normalizados na validação.


---

## 9. Canonicalização

Digests devem operar sobre bytes canônicos versionados. Para JSON, usar canonicalização determinística compatível com RFC 8785 ou equivalente documentado.

O digest não pode depender de indentação, ordem incidental de chaves, locale, timezone implícito ou serializer não versionado.

## 10. Proveniência ampliada

Adicionar quando aplicável:

```json
{
  "source":{"system":"synthetic-producer","instance_id":"producer-01","adapter_version":"1"},
  "causation_id":"uuid",
  "session_id":"synthetic-session",
  "policy_version":"policy/1",
  "sequence":42
}
```

`correlation_id` agrupa uma operação; `causation_id` identifica o evento causador.

## 11. Imutabilidade semântica

- event_id não é reutilizado;
- mesmo event_id com bytes diferentes => CONFLICT;
- reenvio idêntico pode ser idempotente, mas permanece observável;
- correção gera novo evento, nunca update in-place.

## 12. Schema evolution

Breaking change incrementa `schema_version`. Versão desconhecida é recusada, salvo migrador explicitamente versionado.

## 13. Fixtures adicionais

Criar datasets determinísticos para duplicate event, reordered events, malformed identity, stale approval, policy reload, oversized payload, partial export e crash recovery.

## 14. Classificação

PUBLIC/INTERNAL/RESTRICTED são rótulos **sintéticos de POC**. Qualquer categoria institucional futura será mapeada por configuração aprovada, nunca por constantes presumidas.
