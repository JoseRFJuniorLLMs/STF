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
