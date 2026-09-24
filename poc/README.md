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

## Integração com HeraclitusDB real

O adapter somente leitura aceita apenas loopback e foi preparado para superfícies reais como `/sentinel/status`, `/api/v1/agent/status` e `/api/v1/agent/red-team/events`.

Defina `HERACLITUS_URL=http://127.0.0.1:<porta>` para habilitar a leitura. O dashboard standalone continua funcional sem essa integração.


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
