# Baseline Técnico do HeraclitusDB — POC STF

**Baseline original consultado:** commit `8bcdd0a5c881a6be7c965fc36970095cc46f6f6a`.  
**Regra:** fixar novamente o commit imediatamente antes da implementação/qualificação.

## Capacidades relevantes para Fase 1

Foram observados no código/documentação:

### Sentinel

- normalização genérica JSON para `SecurityEvent`;
- provenance para raw event / source LSN;
- replay determinístico em partes qualificadas;
- executor L1 fail-closed;
- subset Sigma documentado;
- `SecuritySignal`;
- grafo temporal de segurança;
- correlation/trust components;
- threat intelligence com diferentes graus de implementação.

A POC deve consultar `STATUS.md` do HeraclitusDB antes de habilitar qualquer submódulo e não promover roadmap a feature pronta.

### HRKL

- append-only;
- LSN/HLC;
- CRC;
- Merkle/BLAKE3;
- canonical encoding;
- proof por LSN;
- validações de integridade.

## Capacidades relevantes para Fase 2

### Agent Gateway

- MCP gateway;
- policy;
- approvals;
- replay rejection;
- identity handling;
- counters;
- red-team evidence.

O laboratório `Agent-Atack-Heraclitus` já usa um princípio que a POC adota: decisão do gateway + `upstream_delta` como evidências independentes.

## Recursos ainda tratados com cuidado

- pacote forense completo da SPEC-0087: Draft/Proposed no baseline;
- Trusted Administration SPEC-0089: Draft/Proposed;
- HSM/KeyProvider gov profile: qualificação posterior;
- threat feeds/TAXII/MISP: graus diferentes de integração;
- qualquer claim de produção depende do STATUS e qualification atuais.

## Decisão arquitetural

A Fase 1 deve **reutilizar Sentinel**, não construir um segundo SIEM paralelo dentro do repositório STF.

O repositório STF fornece:

- adapters/fixtures;
- scenario orchestration;
- qualification;
- synthetic environment;
- evidence packaging POC.

O core de detecção/correlação fica no HeraclitusDB quando já implementado.
