# Remediação da Auditoria Recursiva — POC STF / HeraclitusDB

**Data:** 23/09/2026  
**Origem:** `docs/AUDIT-CODE-3-PASSES-2026-09-23.md`

## Resultado

Todos os achados registrados na auditoria de três passadas foram tratados no código ou convertidos em comportamento explicitamente testado.

| ID | Estado | Remediação |
|---|---|---|
| C-01 | RESOLVIDO | evento não é mais re-hashado após o SecuritySignal; provenance signal→event tem regressão específica |
| C-02 | RESOLVIDO | AS-OF reexecuta detector/correlator sequencialmente e preserva o incidente original |
| C-03 | RESOLVIDO | Evidence Bundle v3 inclui metadata no manifest e verifier valida invariantes semânticos |
| C-04 | RESOLVIDO | reads/snapshots/export usam RLock e deep-copy; teste concorrente verifica bundles durante ingestão |
| H-01 | RESOLVIDO | principal é derivado do componente correlacionado |
| H-02 | RESOLVIDO | WHY usa somente signal_ids do componente do incidente |
| H-03 | RESOLVIDO | entidades são namespaced por tipo: principal/ip/host/db/resource/service |
| H-04 | RESOLVIDO | correlação possui janela HLC/LSN explícita |
| H-05 | RESOLVIDO | incidente aberto fica vinculado ao principal/componente original; segunda campanha não o substitui |
| H-06 | RESOLVIDO | raw_id + source_class possui digest registry: repetição idêntica=IDEMPOTENT; divergente=CONFLICT |
| H-07 | RESOLVIDO | mutações exigem Host/Origin local e `X-STF-POC: 1`; smoke testa 403 |
| H-08 | RESOLVIDO | adapter bloqueia redirects e limita tamanho de resposta |
| H-09 | RESOLVIDO | hashes inválidos retornam FAIL estruturado; verifier não propaga ValueError |
| M-01 | RESOLVIDO | approvals têm created_at/expires_at e expiry é aplicada |
| M-02 | RESOLVIDO | case_write tem fluxo HITL completo quando não está bloqueado por incidente |
| M-03 | RESOLVIDO | qualification/report usam outcomes/reason codes e approvals genéricas; API Lab expõe identity/parameter swap |
| M-04 | RESOLVIDO | tamper-demo atualiza estado; export executa verifier e atualiza offline verification |
| M-05 | RESOLVIDO | adapters validam tipos e handlers retornam erro de validação previsível |
| M-06 | RESOLVIDO | approvals são armazenadas por ID; múltiplas pending coexistem |
| M-07 | RESOLVIDO | inspector verifica hash do conteúdo, elo anterior, elo seguinte e bundle geral |
| M-08 | RESOLVIDO | severidade dinâmica, progresso API Lab, LSN e Time Travel alinhados ao modo externo |

## Novos gates de regressão

A suíte passou a cobrir explicitamente:

- provenance do evento que abre o incidente;
- AS-OF do pipeline externo;
- AS-OF após campanha paralela;
- dedupe e conflito de raw event ID;
- metadata tamper;
- hash não hexadecimal;
- atomicidade do snapshot durante escrita concorrente;
- expiry de approval;
- case_write HITL;
- múltiplas approvals simultâneas;
- janela temporal;
- isolamento por namespace de entidade;
- estabilidade do incidente;
- CSRF/origin local;
- redirect externo do bridge;
- fluxo HTTP completo Telemetry → Incident → Policy → HITL → Replay.

## Arquitetura após a remediação

```text
RAW TELEMETRY
    |
    v
typed validation
    |
    v
normalizer
    |
    v
deterministic detector
    |
    v
SecuritySignal -----> immutable event hash
    |
    v
typed + temporal correlation
    |
    v
stable incident context
    |
    v
policy engine
    |
    +--> DENY -> upstream_delta=0
    |
    +--> REQUIRE_HITL -> approval registry / expiry / binding
    |
    +--> ALLOW -> one upstream effect
    |
    v
immutable event history
    |
    +--> AS-OF reducer
    +--> WHY
    +--> graph
    +--> Evidence Bundle v3
              |
              +--> event Merkle
              +--> metadata manifest
              +--> package_root
              +--> semantic verification
              +--> offline verifier
```

## Limites que permanecem por desenho

A remediação não transforma a POC em piloto institucional. Continuam fora do escopo:

- infraestrutura real do STF;
- logs/credenciais reais;
- HSM/KMS e trust anchors institucionais;
- assinatura/timestamp institucional;
- HA/DR de produção;
- integração write-capable com sistemas reais.

Esses itens são requisitos de piloto/homologação, não bugs da POC.
