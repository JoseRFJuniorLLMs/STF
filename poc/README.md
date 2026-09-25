# POC Executável — HeraclitusDB / STF

Ambiente integralmente sintético e loopback-only que demonstra a campanha descrita nas SPECs do repositório.

## Executar

Requer apenas Python 3.11+.

```bash
cd poc
python server.py
```

Abra `http://127.0.0.1:8787`.

## Testes

```bash
python -m unittest discover -s tests -v
```

## Campanha

1. baseline benigno;
2. sinal de edge/WAF;
3. autenticação anômala;
4. processo incomum;
5. movimento lateral sintético;
6. DB audit anômalo;
7. acesso restrito e abertura de incidente;
8. write pós-compromisso → `DENY`, `upstream_delta=0`;
9. exportação → `REQUIRE_HITL`;
10. aprovação humana vinculada;
11. uma execução permitida;
12. replay → `DENY`;
13. identity swap → `DENY`;
14. parameter swap → `DENY`;
15. tamper → `DETECTED`;
16. Evidence Bundle;
17. verificação offline.

## Endpoints

`GET /api/health`, `GET /api/state`, `POST /api/reset`, `POST /api/step`, `POST /api/run`, `POST /api/tamper-demo`, `POST /api/export`, `GET /api/evidence`, `GET /api/heraclitus-adapter`.

## Segurança

O servidor recusa bind não-loopback. Não há scanner, exploit real, credencial real, subprocesso ofensivo ou chamada externa.

## Simulação 60/30/10 da rede

Os botões **Massivo** (inclusive **Simular rede**) registram tentativas sintéticas no HeraclitusDB. Por componente, cada bloco de dez tentativas produz 6 **defendidas** (detectadas e contidas), 3 **bloqueadas** na entrada e 1 que **chegou ao alvo na simulação**. O destino do modo de rede é sorteado entre os ataques disponíveis. Nenhuma tentativa sintética executa um efeito real no alvo (`upstream_delta=0`). Os testes individuais continuam registrando seus próprios vereditos.

O servidor exige conexão com o HeraclitusDB para gravar a simulação; se o banco estiver indisponível, o disparo falha e o loop para. Os eventos usam a campanha `STF-DEMO-SIMULATION`, e o dashboard os separa dos testes reais. A aba **Incidente 360º** (`#incidente`) mostra os três resultados e todos os componentes. A janela do painel contém os 500 eventos mais recentes do ledger; os percentuais exibidos podem variar até completar blocos de dez por componente ou quando parte da janela contém outros eventos.

Para ajustar os pesos antes de iniciar o servidor, defina `STF_DEMO_DEFENDED_PCT`, `STF_DEMO_BLOCKED_PCT` e `STF_DEMO_TARGET_PCT`. Os três valores devem ser inteiros entre 0 e 100 e somar 100; o padrão é `60`, `30`, `10`. Reiniciar o servidor zera apenas os contadores locais da sequência; os eventos já gravados no HeraclitusDB permanecem no ledger.

## Integração com HeraclitusDB real

O adapter somente leitura aceita apenas loopback e foi preparado para superfícies reais como `/sentinel/status`, `/api/v1/agent/status` e `/api/v1/agent/red-team/events`.

Defina `HERACLITUS_URL=http://127.0.0.1:<porta>` para habilitar a leitura. O dashboard standalone continua funcional sem essa integração.

## Acompanhamento processual

A aba **Acompanhamento processual** mostra só o log de processos fictícios — protocolo, andamentos, deslocamentos e petições — no formato do Acompanhamento Processual do portal do STF e da API pública do DataJud (códigos da Tabela Processual Unificada de movimentos do CNJ; número único da Resolução CNJ 65/2008).

Cada linha é um evento imutável gravado no **núcleo** do HeraclitusDB (gRPC `Append`, encadeado ao anterior por `parents`, com chave de idempotência) e lido de volta por GQL, inclusive `AS OF LSN`.

| Variável | Uso | Padrão |
| --- | --- | --- |
| `HERACLITUS_CORE_ADDR` | núcleo gRPC (só loopback); também `--heraclitus-core` | `127.0.0.1:17474` |
| `STF_HERACLITUS_CORE_TOKEN_FILE` / `STF_HERACLITUS_CORE_TOKEN` | token Bearer quando o núcleo exige RBAC (papel `writer`) | sem token |

O `grpcio` é opcional: sem ele, a aba mostra o HeraclitusDB como indisponível e o resto do painel continua a funcionar. As variáveis `HERACLITUS_TOKEN(_FILE)` **não** são lidas, de propósito, para não enviar a credencial de outra instância.

Endpoints: `GET /api/processos[?as_of=LSN]`, `GET /api/processos/detalhe?id=RE-000001[&as_of=LSN]`, `POST /api/processos/protocolar`, `POST /api/processos/tramitar` (`{"id": "..."}` opcional).

## Defesa Zanin — Laboratório de Prompt Injection

A aba **Defesa Zanin** demonstra a perícia estrutural de documentos contra *Indirect Prompt Injection*, inspirada no incidente relatado em 25/09/2026. A demonstração é **integralmente sintética e independente**.

Capacidades demonstradas:
- **Preservação de bytes originais:** o arquivo nunca é sobrescrito durante a perícia;
- **4 Modos de Exibição:** Humano, Estrutural, Forense (destaque de esteganografia visual e zero-width) e Sanitizado;
- **Forensic Diff:** comparação explícita de conteúdo antes e após a sanitização;
- **Defesa em Duas Barreiras:** mesmo que o detector falhe (MISS programado no Cenário B), o **Policy Gateway** impede que instruções documentais adquiram autoridade operacional (`upstream_delta = 0`);
- **Evidence Bundle & Offline Verifier:** manifesto forense com verificação estrita de integridade e checagens externas marcadas como `UNVERIFIED`.

Consulte [ZANIN-PROMPT-INJECTION-LAB.md](../docs/ZANIN-PROMPT-INJECTION-LAB.md) para a documentação técnica completa.

## Dashboard atual

O painel agora reúne:

- replay automático da campanha com velocidade configurável;
- **Modo apresentação**, com pausas narrativas nos checkpoints relevantes;
- saúde das fontes de telemetria;
- visualização da trilha de ataque;
- grafo temporal do incidente;
- painel **WHY** explicando por que o incidente foi aberto;
- reconstrução **AS-OF por LSN**;
- comparação **Antes × Depois** entre dois pontos do histórico;
- inspector de evidência com **raw telemetry → canonical event**;
- policy/HITL/anti-replay;
- contador independente de efeitos realmente executados;
- hash-chain e raiz Merkle;
- sabotagens separadas: `modify`, `delete`, `reorder` e `truncate`;
- Evidence Bundle e download JSON;
- relatório sintético do incidente e download JSON;
- bridge read-only para HeraclitusDB real em loopback.

## Roteiro rápido de apresentação

1. Execute `python server.py`.
2. Abra `http://127.0.0.1:8787`.
3. Ative **Modo apresentação**.
4. Clique **Executar campanha**.
5. No primeiro checkpoint, mostre o painel **Por que este incidente?** e as fontes de telemetria.
6. No segundo checkpoint, explique a passagem da Fase 1 para a policy da Fase 2.
7. No checkpoint do HITL, destaque que somente a ação aprovada aumenta `upstream_hits`.
8. No checkpoint de tamper, execute também uma sabotagem manual escolhendo `modify`, `delete`, `reorder` ou `truncate`.
9. Use **Time Travel** e **Antes × Depois** para reconstruir o estado em diferentes LSNs.
10. Abra o **Inspector de evidência** e mostre o log bruto, o evento normalizado, o hash e o elo da cadeia.
11. Gere o **Evidence Bundle**.
12. Baixe o relatório e o pacote de evidências.

## Endpoints adicionais

```text
GET /api/source-health
GET /api/why
GET /api/asof?lsn=N
GET /api/compare?from=A&to=B
GET /api/evidence/object?lsn=N
GET /api/evidence/download
GET /api/report
GET /api/report/download
GET /api/heraclitus-adapter
POST /api/tamper-demo?kind=modify|delete|reorder|truncate
```

## Telemetria bruta

`telemetry.py` implementa normalizadores vendor-neutral para:

- firewall/WAF;
- IAM;
- host;
- rede;
- banco;
- aplicação.

Os eventos usam somente identidades, hosts e endereços sintéticos ou reservados para documentação. O dado bruto é preservado junto do resultado normalizado para que o analista possa auditar a transformação.


## Fault injection

O dashboard possui cenários controlados de resiliência:

- `policy_store_down`: ação HIGH falha fechada em `DENY`;
- `timeout_before_effect`: estado inicial `UNKNOWN`, reconciliado com `upstream_delta=0`;
- `timeout_after_effect`: estado inicial `UNKNOWN`, reconciliado com `upstream_delta=1`;
- `exporter_interrupted`: falha do exporter não modifica a história canônica;
- `clock_jump`: relógio de origem pode regredir sem reordenar LSN/HLC.

Esses cenários não atacam serviços reais; exercitam a semântica de erro e reconciliação da POC.


## Ingestão externa local

Além do cenário embutido, o servidor aceita telemetria bruta por HTTP **somente porque ele próprio está limitado a loopback**:

```text
POST /api/telemetry?kind=firewall
POST /api/telemetry?kind=identity
POST /api/telemetry?kind=host
POST /api/telemetry?kind=network
POST /api/telemetry?kind=db
POST /api/telemetry?kind=app
```

Exemplo com dado reservado para documentação:

```bash
curl -X POST "http://127.0.0.1:8787/api/telemetry?kind=firewall" \
  -H "Content-Type: application/json" \
  -H "X-STF-POC: 1" \
  -d '{"event_id":"LAB-1","src_ip":"203.0.113.42","dst_service":"portal-synthetic","action":"OBSERVED","waf_score":71}'
```

O caminho executado é:

```text
raw JSON
  -> adapter vendor-neutral
  -> canonical telemetry
  -> detector
  -> SecuritySignal (quando houver regra)
  -> correlação por entidades
  -> incidente
  -> HRKL/evidence do harness
```

O corpo é limitado a 64 KiB e deve ser um objeto JSON.
