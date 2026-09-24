# Auditoria Recursiva de Código — 3 Interações

**Projeto:** STF POC / HeraclitusDB  
**Data:** 23/09/2026  
**Escopo:** `poc/`, testes e workflow de CI  
**HEAD auditado:** `163d1601c4780a5d78093892bc46cc62ca9c6451` e evoluções posteriores somente documentais da auditoria  
**Método:** três passadas independentes: lógica local, invariantes ponta a ponta e adversarial/forense.

> Esta auditoria não altera a implementação. O objetivo é registrar falhas antes de corrigi-las e impedir que um CI verde seja confundido com ausência de bugs.

## Sumário

A POC é funcional e possui boa cobertura do cenário feliz, negativos de policy e smoke HTTP. Entretanto, a auditoria encontrou falhas que precisam ser corrigidas antes de tratar a camada forense como qualificada.

### Severidade

| ID | Severidade | Área | Achado |
|---|---|---|---|
| C-01 | CRITICAL | Provenance | Signal pode apontar para hash antigo do evento que abre o incidente |
| C-02 | CRITICAL | Time Travel | AS-OF usa lógica legada e reconstrói estado diferente do motor atual |
| C-03 | CRITICAL | Evidence | Metadados do pacote não estão cobertos pelo manifest/package root |
| C-04 | CRITICAL | Concorrência | Reads/exports não compartilham lock consistente com writes |
| H-01 | HIGH | Incident | Principal do incidente é hard-coded |
| H-02 | HIGH | Explainability | WHY inclui sinais fora do componente correlacionado |
| H-03 | HIGH | Correlation | Entidades sem namespace podem fundir campanhas independentes |
| H-04 | HIGH | Correlation | Não existe janela temporal/expiração de sinais |
| H-05 | HIGH | Incident | Componente “best” posterior pode substituir evidência de incidente aberto |
| H-06 | HIGH | Ingest | Sem idempotência/conflito por raw event_id |
| H-07 | HIGH | Local API | Rotas mutáveis de localhost não têm proteção de Origin/CSRF |
| H-08 | HIGH | Adapter | urllib segue redirect e pode escapar do loopback |
| H-09 | HIGH | Verifier | Hash hex inválido de 64 chars pode lançar exceção em vez de FAIL |
| M-01 | MEDIUM | HITL | Approval declara expires_in mas nunca expira |
| M-02 | MEDIUM | Policy | case_write pode retornar REQUIRE_HITL sem criar approval utilizável |
| M-03 | MEDIUM | API Lab | Report/qualification dependem de IDs/tipos do roteiro embutido |
| M-04 | MEDIUM | State | offline_verify/tamper_status não refletem operações equivalentes do API Lab |
| M-05 | MEDIUM | Input | Alguns campos mal tipados geram AttributeError fora do tratamento 400 |
| M-06 | MEDIUM | HITL | Um único pending_approval global limita concorrência e pode interferir entre clientes |
| M-07 | MEDIUM | Evidence | Inspector verifica só elo anterior, não integridade completa do objeto |
| M-08 | MEDIUM | UI | Severidade/progresso/time-travel têm inconsistências no modo externo |

---

# Interação 1 — Correção estática e lógica local

## C-01 — Hash de provenance fica obsoleto quando o incidente abre

Arquivos:
- `poc/server.py::_signal`
- `poc/server.py::_maybe_open_incident`
- `poc/server.py::ingest_telemetry`
- `poc/server.py::step`

Sequência atual:

1. `_append()` calcula `event_hash`;
2. `_signal()` copia esse hash para `signal.evidence_hash`;
3. a correlação abre o incidente;
4. `incident_id` é inserido no evento;
5. `event_hash` é recalculado;
6. o signal mantém o hash anterior.

Impacto:

```text
SecuritySignal.evidence_hash != EvidenceEvent.event_hash
```

Isso quebra provenance sem quebrar a hash-chain.

Correção indicada:
- definir `incident_id` antes do hash final; ou
- recalcular/atualizar refs derivadas atomicamente; idealmente derivação posterior ao persist final.

Teste obrigatório:
`signal_evidence_hash_matches_final_event_hash_on_incident_open`.

## C-02 — AS-OF não reconstrói o motor real atual

`as_of()` calcula:

```python
risk = sum(int(e.details.get("risk",0)) for e in events)
if risk >= 60:
    incident = ...
```

Mas o runtime atual abre incidente usando:
- detector;
- entidades;
- componentes;
- `correlate()`;
- `best.qualifies`.

No API Lab, eventos externos nem possuem o campo legado `risk`. Assim é possível ter:

```text
estado vivo: incident=OPEN
AS-OF no mesmo LSN: incident=NONE
```

Correção indicada:
- replay determinístico dos eventos até LSN;
- reexecutar detector/correlator/policy reducer versionado;
- não derivar state histórico por heurística paralela.

## C-03 — Package root não cobre metadados do envelope

O manifest cobre:
- events;
- signals;
- incident;
- attack_graph;
- qualification;
- trust;
- limitations.

Ficam fora da autenticação semântica direta:
- schema_version;
- package_id;
- campaign_id;
- incident_id;
- generated_at_claimed;
- event_count;
- lsn_range.

O verifier também não exige:
- `event_count == len(events)`;
- LSNs sequenciais;
- lsn_range correto;
- campaign_id consistente nos eventos/signals;
- signal.evidence_hash apontando para evento existente.

Correção indicada:
- manifestar também `metadata.json`;
- verificar invariantes semânticos além de hashes.

## C-04 — ThreadingHTTPServer com reads sem snapshot atômico

Writes principais usam `self.lock`, mas métodos como:
- `evidence_bundle()`;
- `snapshot()`;
- `source_health()`;
- `why_incident()`;
- `as_of()`;
- `incident_report()`

podem ser chamados por GET concorrente sem o mesmo lock.

Impacto:
- export pode misturar events de T1 com signals/incident de T2;
- resposta pode serializar referência mutável após retorno do método;
- package root pode representar um snapshot que nunca existiu logicamente.

Correção indicada:
- snapshot imutável/deep-copy sob RLock;
- export/verifier operam somente no snapshot congelado.

---

# Interação 2 — Invariantes ponta a ponta e testes

## H-01 — Principal do incidente hard-coded

`_maybe_open_incident()` sempre usa:

```python
"principal": COMPROMISED_PRINCIPAL
```

Mesmo que telemetria externa correlacione outra identidade.

Impacto:
- incident context incorreto;
- policy pode deixar de bloquear a identidade realmente correlacionada.

Correção:
- extrair principal tipado do componente vencedor.

## H-02 — WHY inclui sinais que não pertencem ao incidente

`why_incident()` itera todos os `self.signals`, não apenas:
- `incident.correlation.signal_ids`;
- `incident.evidence_lsns`.

Com segunda campanha/desvio benigno, o WHY pode atribuir causa falsa ao incidente.

Além disso, `threshold: 60` é resíduo da lógica antiga; o correlator atual qualifica estruturalmente.

## H-03 — Entidades sem tipo/namespace fundem contextos

`correlation._entities()` trabalha com strings simples.

Exemplos de entidades genéricas incluídas pelos detectors:
- `identity-provider`;
- `portal-synthetic`;
- nomes de DB compartilhados.

Duas identidades distintas podem ficar conectadas porque compartilham o mesmo asset genérico.

Correção:
- entidades tipadas, por exemplo:
  - `principal:service-account-17`;
  - `ip:203.0.113.42`;
  - `host:srv-app-07`;
  - `db:db-judicial-lab`;
- classificar quais tipos criam aresta de causalidade.

## H-04 — “Temporal correlation” não possui janela temporal

`correlate()` considera todos os signals desde reset.

Logo sinais muito antigos podem ser unidos a sinais novos.

Correção:
- claimed time + ingest HLC;
- janela configurável;
- expiração/decay;
- teste de sinais relacionados fora da janela.

## H-05 — Incidente aberto pode trocar de componente

Depois de aberto, `_maybe_open_incident()` recalcula `best` sobre todos os sinais e sobrescreve:

- risk_score;
- evidence_lsns;
- correlation;
- correlation_explanation.

Uma segunda campanha mais forte pode “roubar” o incidente existente.

Correção:
- incident_id por componente/campanha;
- componentes estáveis;
- atualizar um incidente somente com sinais compatíveis com sua identidade causal.

## H-06 — Raw event id não é idempotente

`CanonicalTelemetry.raw_id` é preservado, mas o engine não mantém registry.

Hoje:
- mesmo event_id + mesmos bytes => novo LSN;
- mesmo event_id + bytes diferentes => também novo LSN.

Isso contradiz o contrato das SPECs.

Correção:
- índice `source_class + raw_id -> payload_digest`;
- repetição idêntica => IDEMPOTENT;
- mesmo ID / digest diferente => CONFLICT.

## Cobertura que falta no CI

Atualmente faltam testes de:
- AS-OF externo;
- stale signal evidence hash;
- metadata tamper;
- malformed 64-char non-hex hash;
- dedupe/conflict;
- two-campaign contamination;
- time-window expiration;
- concorrência de GET/export durante writes;
- CSRF/origin;
- redirect externo no adapter.

---

# Interação 3 — Adversarial, segurança e falsos-verdes

## H-07 — CSRF contra API loopback

O bind em 127.0.0.1 não impede um site aberto no navegador de enviar requisições para localhost.

Rotas mutáveis sem Origin/token incluem:
- `POST /api/reset`;
- `POST /api/step`;
- `POST /api/run`;
- `POST /api/tamper-demo`;
- `POST /api/fault-demo`;
- `POST /api/export`.

CORS impede leitura por outro origin, mas não necessariamente o envio da ação.

Correção:
- validar `Origin`/Host;
- nonce/token de sessão;
- exigir JSON + header não-simple nas mutações;
- Same-Origin explícito.

## H-08 — Redirect pode furar a garantia loopback do adapter

`HeraclitusAdapter` valida o hostname inicial, porém usa `urllib.request.urlopen`, que segue redirects.

Um serviço local pode responder:

```text
302 Location: https://host-externo/...
```

e o cliente segue o destino.

Correção:
- desabilitar redirects; ou
- validar URL final após cada redirect;
- impor limite de bytes da resposta.

## H-09 — Hash não hexadecimal pode derrubar verifier

A verificação aceita qualquer string de comprimento 64 para a lista e depois executa `bytes.fromhex`.

Exemplo:
```text
event_hash = "z" * 64
```

pode gerar `ValueError` em vez de resultado `FAIL`.

Correção:
- parse hex seguro;
- qualquer erro criptográfico => FAIL estruturado, nunca exception.

## M-01 — Approval nunca expira

A approval possui:

```text
expires_in = 5m
```

mas nenhuma timestamp de criação/expiração e nenhuma validação no policy engine.

Resultado: approval APPROVED continua válida indefinidamente até consumo/reset.

## M-02 — case_write REQUIRE_HITL é um estado sem caminho de approval

`policy.decide(case_write)` pode retornar `REQUIRE_HITL`.

Mas `submit_action()` só cria `pending_approval` quando:

```python
decision.requires_human and action == "export_restricted"
```

Logo um case_write que exige humano não tem fluxo para ser aprovado.

## M-03 — Report e qualification são acoplados ao roteiro embutido

Exemplos:
- HITL exige `"APR-001" in approvals_consumed`;
- anti-replay no report exige `event_type=="approval.replay"`;
- API Lab usa IDs `APR-LAB-...` e replay externo pode manter tipo genérico.

Assim o fluxo API pode funcionar corretamente e o relatório ainda dizer `PENDING`.

## M-04 — Estado visual diverge no API Lab

- `tamper_status` é atualizado pelo passo roteirizado, não pelo botão tamper-demo;
- `offline_verify` é atualizado pelo cenário, não pela verificação real do bundle externo;
- scorecard final pode permanecer pendente após pipeline externo correto.

## M-05 — Tipos inválidos podem escapar como AttributeError

Exemplos:
- `normalize_host(): raw["os"].lower()`;
- `normalize_db(): raw["operation"].lower()`;
- `normalize_app(): raw["action"].lower()`.

O handler captura `ValueError/KeyError/TypeError`, não `AttributeError`.

Payloads mal tipados podem encerrar o handler daquela request em vez de produzir 400 consistente.

## M-06 — Um único pending_approval global

Há apenas:
```python
self.pending_approval
```

Sem request ID/mapa.

Duas operações simultâneas podem interferir no mesmo slot lógico. O RLock evita double-spend local, mas não resolve multiplexação de approvals.

## M-07 — Inspector chama de válido um elo parcial

`evidence_object().chain_link_valid` verifica apenas:

```text
current.prev_hash == previous.event_hash
```

Não verifica:
- hash do conteúdo atual;
- next.prev_hash == current.event_hash;
- membership no Merkle/package.

A UI deve chamar isso de “previous-link valid” ou fazer prova completa.

## M-08 — Inconsistências menores de UI

- badge do incidente mostra `OPEN / HIGH` mesmo quando severity pode virar CRITICAL;
- API Lab marca progresso 100% após o primeiro evento externo;
- Time Travel local usa `step_index`, que permanece 0 no modo externo;
- slider pode mostrar “antes do primeiro evento” apesar de já haver vários LSNs externos.

---

# Prioridade de correção

## P0 — antes de nova demonstração técnica

1. C-01 provenance/hash stale.
2. C-02 AS-OF determinístico pelo mesmo reducer/correlation.
3. C-03 metadata + semantic verification.
4. C-04 snapshot/locking.
5. H-01/H-02 identidade e WHY corretos.
6. H-03/H-04/H-05 correlação estável, tipada e temporal.
7. H-06 dedupe/conflict.

## P1 — antes de chamar a POC de endurecida

8. H-07 Origin/CSRF.
9. H-08 redirect loopback.
10. H-09 verifier fail-safe.
11. M-01 expiry.
12. M-02 HITL para case_write.
13. M-03/M-04 unificar scripted/API Lab qualification.

## P2 — acabamento

14. approval registry multi-request.
15. inspector com prova completa.
16. correções de UI.

# Conclusão

O CI verde atual prova que os cenários cobertos funcionam. Ele **não prova ainda** consistência forense completa sob concorrência, replay de collector ou múltiplas campanhas.

A POC continua demonstrável, mas quatro achados críticos atingem diretamente as claims mais importantes: provenance, reconstrução histórica, integridade do pacote e atomicidade do snapshot.

A correção deve começar por esses quatro pontos antes de ampliar novas features.
