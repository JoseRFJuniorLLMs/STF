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
