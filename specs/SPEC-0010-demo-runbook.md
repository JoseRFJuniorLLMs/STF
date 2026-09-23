# SPEC-0010 — Runbook da Demonstração Técnica

**Status:** Proposed  
**Classe:** Demo / Acceptance Runbook  
**Prioridade:** P0  
**Dependências:** SPEC-0001 a SPEC-0009

## 1. Objetivo

Definir uma demonstração de 30 a 45 minutos que seja técnica, reproduzível e verificável.

## 2. Regra

A demo não depende de slides para provar propriedades. Slides podem explicar; scripts e resultados devem provar.

## 3. Preparação

Antes da reunião:

- ambiente limpo;
- hashes validados;
- fixtures carregáveis;
- logs zerados;
- clock registrado;
- versão do HeraclitusDB registrada;
- branch/commit da POC registrados;
- plano B local sem internet.

## 4. Sequência

### Fase A — Introdução, 3–5 min

Explicar:

- camada lateral;
- dados sintéticos;
- nenhum acesso a produção;
- objetivo de provar controle e evidência.

### Fase B — Ingestão e histórico, 5 min

Executar cenário base.

Mostrar:

```text
events accepted
LSN range
Merkle root
current state
```

### Fase C — Time travel, 3 min

Consultar estado antes e depois de alteração.

Mostrar diferença entre:

- aprovação;
- execução;
- estado corrente.

### Fase D — Agente, 7 min

Executar:

1. tool LOW => ALLOW;
2. tool HIGH => REQUIRE_HITL;
3. rejeitar => DENY;
4. repetir com nova solicitação;
5. aprovar => PASS.

### Fase E — Ataques, 7 min

Executar:

- replay;
- expiração;
- identity mismatch;
- alteração de parâmetros.

Todos devem produzir DENY.

### Fase F — Evidência, 5 min

Exportar bundle.

Desligar/parar origem quando possível.

Rodar verificador independente.

### Fase G — Sabotagem, 5 min

Editar um objeto do bundle.

Rodar verificador novamente.

Exigir FAIL/DETECTED.

## 5. Comandos alvo

A implementação deverá convergir para interface semelhante a:

```bash
./poc up
./poc seed
./poc scenario happy
./poc scenario agent
./poc attack replay
./poc attack identity
./poc export POC-STF-001
./poc verify ./out/POC-STF-001
./poc tamper ./out/POC-STF-001
./poc verify ./out/POC-STF-001
```

Os nomes podem mudar. A propriedade “um comando por etapa” permanece.

## 6. Tela final

A última saída deve consolidar:

```text
HISTORY_APPEND_ONLY       PASS
TIME_TRAVEL               PASS
HIGH_ACTION_WITHOUT_HITL  DENY
HIGH_ACTION_WITH_HITL     PASS
REPLAY                     DENY
EXPIRED_APPROVAL           DENY
IDENTITY_MISMATCH          DENY
EVIDENCE_EXPORT            PASS
OFFLINE_VERIFY             PASS
TAMPER_AFTER_EXPORT        DETECTED
EXTERNAL_TIMESTAMP         NOT_CONFIGURED
INSTITUTIONAL_SIGNATURE    NOT_CONFIGURED
```

## 7. Falha em demo

Nunca esconder falha.

Se um cenário não atingir o esperado:

- manter saída;
- marcar FAIL;
- registrar correlation_id;
- não substituir por explicação verbal.

Isso preserva credibilidade e transforma a POC em diagnóstico útil.


---

## 8. Preflight obrigatório

```text
POC_COMMIT                 PASS
HERACLITUS_BASELINE        PASS
WORKTREE_CLEAN             PASS
ARTIFACT_HASHES            PASS
FIXTURES                   PASS
POLICY_VERSION             PASS
UPSTREAM_COUNTER_ZERO      PASS
NETWORK_PROFILE            PASS
OFFLINE_VERIFIER_READY     PASS
```

## 9. Run ID

Cada apresentação gera `run_id` único:

```text
out/<run_id>/logs
out/<run_id>/tests
out/<run_id>/evidence
out/<run_id>/metrics
```

Nenhum artefato de execução anterior pode contaminar a atual.

## 10. Roteiro de 38 minutos

- 0–4: problema e limites;
- 4–8: arquitetura/trust boundaries;
- 8–13: ingestão + Merkle;
- 13–17: time travel;
- 17–24: agente + HITL;
- 24–30: replay/identity/TOCTOU;
- 30–34: export + offline verify;
- 34–37: sabotagem;
- 37–38: scorecard.

## 11. Demo anti-teatro

Antes do ataque, mostrar EXPECTED. Em seguida executar comando sem editar configuração. Mostrar OBSERVED e upstream_delta.

Exemplo:

```text
EXPECTED replay: DENY / upstream_delta=0
OBSERVED: DENY / REPLAY_DETECTED / upstream_delta=0
TEST: PASS
```

## 12. Plano B

Manter ambiente local, resultado da última execução qualificada e gravação curta opcional apenas como contingência. Material gravado nunca será apresentado como execução ao vivo.

## 13. Perguntas que a POC responde

- O que foi executado?
- Quem/qual agente pediu?
- Qual política decidiu?
- Houve aprovação?
- Algo mudou entre approval e execute?
- Quantas vezes o upstream foi atingido?
- A prova continua válida com a origem desligada?
- O que a POC não prova?

## 14. Encerramento

Exibir scorecard gerado automaticamente e limitações no mesmo painel. Checks UNVERIFIED/NOT_CONFIGURED não podem ser escondidos por slides.
