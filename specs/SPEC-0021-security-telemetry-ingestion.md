# SPEC-0021 — Security Telemetry Ingestion

**Status:** Proposed  
**Fase:** 1 — Invasão  
**Prioridade:** P0  
**Dependências:** SPEC-0002, SPEC-0003

## 1. Objetivo

Construir uma malha de ingestão sintética capaz de representar as classes de telemetria relevantes para um ambiente institucional semelhante, em alto nível, ao perfil público do STF.

A POC não conecta em sistemas reais.

## 2. Fontes P0

```text
FW          edge/network decision
WAF         application-edge signal
IDENTITY    login/session/context
LINUX       process/file/auth
WINDOWS     process/service/auth
NETWORK     DNS/proxy/connection
DB          query/write/audit
APP         resource/action/audit
```

Fontes P1:

- backup/protection;
- dev tooling;
- API gateway;
- AI/HPC workload;
- data platform.

## 3. Adapter contract

Cada adapter produz `SecurityEvent` canônico e preserva:

- source class;
- raw source id;
- raw event digest;
- claimed time;
- ingest time;
- adapter version;
- source sequence quando houver;
- parsing status;
- normalization warnings.

## 4. Raw-first

O dado bruto ou sua representação preservável deve ser persistido antes/ao lado do derivado suficiente para permitir provenance.

```text
RAW EVENT
  -> canonical SecurityEvent
  -> SecuritySignal
```

O sinal nunca substitui o evento bruto.

## 5. Backpressure

A ingestão deve possuir limites explícitos:

- max event bytes;
- queue depth;
- batch size;
- rate;
- malformed-event handling.

Overflow não pode virar perda silenciosa.

Estados possíveis:

`ACCEPTED REJECTED DROPPED_BY_POLICY BACKPRESSURE`.

## 6. Clock

Registrar:

- `source_claimed_time`;
- `ingest_time`;
- HLC/LSN quando persistido.

Não ordenar a campanha somente pelo relógio da fonte.

## 7. Testes

| ID | Caso | Esperado |
|---|---|---|
| ING-01 | evento FW válido | PASS |
| ING-02 | evento Identity válido | PASS |
| ING-03 | Linux/Windows | PASS |
| ING-04 | DB audit | PASS |
| ING-05 | App audit | PASS |
| ING-06 | payload malformado | REJECT |
| ING-07 | evento oversized | REJECT |
| ING-08 | replay idêntico | idempotente/observável |
| ING-09 | mesmo ID, bytes diferentes | CONFLICT |
| ING-10 | source timestamp absurdo | flag sem perder ingestão conforme policy |

## 8. Realismo STF

Os adapters usam classes coerentes com sistemas e infraestrutura publicados pelo STF, mas permanecem vendor-neutral quando o fabricante atual não é publicamente confirmado.
