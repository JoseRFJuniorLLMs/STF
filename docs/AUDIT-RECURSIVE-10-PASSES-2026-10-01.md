# Auditoria Recursiva em 10 Passadas — STF POC / HeraclitusDB

**Data:** 01/10/2026  
**Baseline auditado:** 991c1a679c356f8f3b09b1b373c8f8005fbb3b44  
**Escopo:** repositório JoseRFJuniorLLMs/STF completo: POC Python, dashboard, adapter HeraclitusDB, núcleo gRPC, log processual, SPEC-0028, testes, CI, documentação, scripts operacionais e deploy.  
**Método:** dez passadas recursivas. Cada achado foi rechecado em passadas posteriores contra implementação, testes, documentação e comportamento esperado antes de permanecer neste relatório.

## 1. Resumo executivo

O projeto possui uma base de testes substancial: o CI do baseline executou **119 testes**, HTTP smoke e gate de sintaxe JavaScript com resultado verde. Há boas proteções de loopback, fail-closed de policy, anti-replay, binding de identidade/parâmetros, verificação de cadeia, tamper tests, negative controls e um cenário explícito de detector-MISS para a SPEC-0028.

A auditoria encontrou, porém, falhas reais fora da cobertura atual. As mais importantes estão no **significado da persistência e do failover**: em certos caminhos uma falha real do HeraclitusDB pode ser apresentada como aceite/persistência, e o log processual pode trocar silenciosamente para memória volátil enquanto a interface continua parecendo conectada a um ledger real.

**Resultado consolidado:** 0 críticos, 4 altos, 8 médios e 3 baixos.

Não foi encontrado exploit remoto crítico direto no servidor da POC durante esta auditoria. Isso não equivale a prontidão institucional: os achados altos atingem proveniência, veracidade de claims e continuidade do ledger, que são centrais para a proposta.

---

## 2. As dez passadas

### Passada 1 — Inventário, histórico e CI
Inventário recursivo, baseline, workflows, superfícies de complexidade e auditorias anteriores. O CI estava verde; server.py e app.js continuam concentrando muitas responsabilidades.

### Passada 2 — Fronteiras HTTP, loopback e mutações
Revisados bind loopback, Host/Origin, X-STF-POC, limites de body, redirect handling e superfícies REST. As correções de CSRF/redirect/loopback da auditoria anterior estão presentes.

### Passada 3 — Policy, estado, concorrência e integridade
Revisados HITL, replay, identity/action/parameter binding, snapshots, Evidence Bundle, verifier e upstream oracle. Os principais invariantes continuam coerentes.

### Passada 4 — Persistência real e adapter
Revisados heraclitus_adapter.py e seus consumidores. Resultado: H-01, false positive de persistência.

### Passada 5 — Frontend, escaping e navegação
Revisados innerHTML, escaping, atributos inline, tabelas, attack_id e Log Visual. A maior parte do conteúdo é escapada; permanece risco de contexto JavaScript inline.

### Passada 6 — Document/LLM Security
Revisados SPEC-0028, zanin_defense.py, detector, quarantine, DATA_ONLY, detector-MISS, controle benigno e Evidence Bundle. Os invariantes centrais têm testes e a limitação de parser sintético está documentada.

### Passada 7 — Failover e regressão
Revisados ResilientMemoryCore, ProcessLedger, falha em query e falha em append. Resultado: H-02 e H-03. Não existe teste do cenário “read real passa, append real falha”.

### Passada 8 — CI, supply chain e deploy
Revisados workflow, SPEC-0015, SPEC-0016 e deploy.md. O CI é útil, mas incompleto; o deploy manual ficou defasado em relação aos módulos atuais.

### Passada 9 — Claims técnicos, jurídicos e institucionais
Revisadas afirmações sobre imutabilidade, não-repúdio, RPO, dados reais, certidão, indisponibilidade e resistência a administradores. Resultado: H-04 e claims médios a rebaixar.

### Passada 10 — Recursão e eliminação de falsos positivos
Todos os achados foram comparados novamente com testes, CI #156, código atual, docs e escopo sintético. Problemas já remediados em setembro foram descartados.

---

# 3. Achados ALTOS

## H-01 — Falha de persistência pode virar accepted=true

**Arquivos:** poc/heraclitus_adapter.py, poc/server.py e poc/dashboard/auditoria.js.

### Evidência

HeraclitusAdapter.record_red_team_event() captura qualquer exceção do POST e retorna algo equivalente a:

~~~python
{
    "accepted": True,
    "lsn": int(event_data.get("sequence") or 1),
    "fallback": True,
    "error": str(exc)
}
~~~

Consumidores em server.py tratam accepted como confirmação e podem registrar heraclitus_persisted=true e um LSN sintético. A interface de auditoria pode então exibir “Recibo de aceite do HeraclitusDB”.

### Impacto

Indisponibilidade, 401/403, incompatibilidade de schema, timeout ou outro erro podem virar afirmação de persistência. Para um sistema cujo valor é evidência/proveniência, FAILED ou UNKNOWN nunca pode ser convertido em PERSISTED.

### Correção

Em falha, retornar accepted=false, persisted=false e lsn=null. Se houver fallback local, usar storage_mode=LOCAL_FALLBACK, durability=VOLATILE e heraclitus_persisted=false.

### Gate

~~~text
adapter POST falha
 -> accepted == false
 -> heraclitus_persisted == false
 -> heraclitus_lsn == null
 -> UI não mostra recibo de aceite
~~~

---

## H-02 — Fallback de memória é apresentado como se fosse ledger HeraclitusDB

**Arquivos:** poc/processos.py, poc/server.py, poc/dashboard/processos.js, poc/dashboard/log-visual.js e poc/README.md.

Ao receber CoreUnavailable, ProcessLedger ativa _use_fallback e passa a responder a partir de ResilientMemoryCore.

Esse fallback é memória de processo, não HRKL durável. Ele gera LSN e IDs próprios, desaparece no restart e pode ser pré-populado com roteiro sintético.

Porém listar() e detalhe() não expõem storage_mode, durability, fallback_active nem source. A UI pode seguir exibindo CONECTADO, Log HeraclitusDB e log imutável.

Há ainda contradição documental: poc/README.md afirma que sem gRPC a aba mostra HeraclitusDB indisponível, enquanto o código atual pode servir memória.

### Correção

API deve expor explicitamente:

~~~json
{
  "storage_mode": "HERACLITUS_CORE ou MEMORY_FALLBACK",
  "durability": "DURABLE ou VOLATILE",
  "fallback_active": false,
  "core_connected": true
}
~~~

A UI deve usar badge “MEMORY FALLBACK — NÃO DURÁVEL” quando for o caso.

---

## H-03 — Failover durante Append pode quebrar continuidade e cadeia

**Arquivo:** poc/processos.py.

### Cenário

1. _eventos() consulta o núcleo real com sucesso.
2. Existem eventos 1..N no HeraclitusDB.
3. tramitar() calcula o pai como evento N.
4. _gravar() tenta core.append().
5. O core fica indisponível nessa etapa.
6. O código troca para fallback_core.
7. O fallback pode estar vazio.
8. O evento N+1 é gravado em RAM apontando para um pai inexistente nesse fallback.

O caminho de exceção de append não pré-popula nem replica um snapshot consistente do real.

### Efeitos

Cadeia incompleta, seq iniciando em N+1, parent ausente, namespace de LSN artificial, perda no restart e ausência de reconciliação posterior.

ResilientMemoryCore ainda inicia LSN em valor fixo 3240, sem namespace seguro perante o core real.

### Correção

Preferência: fail closed para escrita processual enquanto não existir um WAL de failover real.

Se failover offline for requisito, precisa de snapshot consistente, IDs separados, journal durável, origem FALLBACK explícita, fila de reconciliação e conflito formal.

### Gate

~~~text
query real PASS
append real CoreUnavailable
 -> não fabricar continuidade
 -> não marcar persisted
 -> cadeia não é declarada íntegra indevidamente
 -> estado de failover aparece na API/UI
~~~

---

## H-04 — Claims institucionais e criptográficos excedem a prova

**Arquivos:** poc/dashboard/zanin.js, poc/dashboard/resiliencia.js e poc/dashboard/index.html.

A UI contém afirmações como:

- “Ninguém — nem os técnicos do tribunal — consegue alterar ou forjar a evidência”.
- “Garantia de Não-Repúdio”.
- “RPO=0s”.
- “100% PARIDADE”.
- desligamento abrupto sem perda.
- “Emitir Certidão Oficial de Indisponibilidade”.

Hash-chain/Merkle local não prova resistência a operador com controle do mesmo host, código, storage e trust anchors. Isso exigiria WORM/external retention, HSM/KMS, TSA, assinaturas independentes, separation of duties e trust externo.

A POC também é declaradamente não oficial, portanto sua saída não pode se chamar “Certidão Oficial”.

A Lei 11.419/2006, art. 10, §2º prevê prorrogação automática quando o sistema judicial aplicável fica indisponível por motivo técnico no contexto legal. A POC, porém, não é esse sistema oficial e seu registro sintético não produz o efeito jurídico por si só.

### Correção de linguagem

Usar claims verificáveis:

~~~text
“a POC detecta adulteração dentro do modelo testado”
“a cadeia local valida neste snapshot”
“RPO observado no cenário sintético: ...”
“Certidão sintética de demonstração — sem efeito oficial”
“simulação da regra de prorrogação; não produz efeito processual”
~~~

---

# 4. Achados MÉDIOS

## M-01 — Erro de decode/query vira lista vazia

Em poc/heraclitus_core.py, HeraclitusCore.query() pode capturar erro de JSON/shape e devolver lista vazia. Isso confunde resposta corrompida ou protocolo incompatível com “nenhum evento”.

**Correção:** CoreProtocolError explícito e estado INVALID_RESPONSE.

## M-02 — Evidence Bundle sem limite de tamanho

poc/heraclitus_adapter.py, get_bundle_bytes(), lê a resposta inteira sem limite equivalente ao aplicado às superfícies JSON.

**Correção:** MAX_BUNDLE_BYTES e leitura incremental.

## M-03 — CI não testa integração DOM/UI

O gate JavaScript é sintaxe. Evidência concreta: a implementação do Log Visual passou no CI mesmo quando a view existia mas o botão da aba ainda não havia sido inserido.

**Correção:** teste headless, preferencialmente Playwright, validando pares tab/view, troca de todas as abas e erros de console.

## M-04 — CI não implementa integralmente SPEC-0015/SPEC-0016

Faltam SBOM, vulnerability scan, license/dependency inventory, artifacts de qualification, mutation gates, secret scan e build provenance. As GitHub Actions também são referenciadas por versão major, não SHA fixo no YAML.

## M-05 — Cobertura de paths do CI é incompleta

O workflow não cobre diretamente zera.py, deploy.md, specs/**, docs/** e scripts raiz. Em pull_request, README.md também não é gatilho.

## M-06 — attack_id interpolado em JavaScript inline

processos.js, incidente.js e auditoria.js montam handlers inline contendo IDs em string JavaScript. Hoje os IDs críticos vêm majoritariamente de catálogo fixo, então a explorabilidade atual é limitada.

**Correção:** data-attack-id + event delegation. HTML escaping não é escaping de string JavaScript.

## M-07 — zera.py usa shell=True em operação destrutiva

O script combina shell=True, sudo rm -rf e backup com check=False. DATA_DIR é constante hoje, portanto não é command injection exposta ao usuário, mas a robustez operacional é inadequada.

**Correção:** argv sem shell, caminho canônico permitido, backup obrigatório, dry-run e falha antes de purge.

## M-08 — Runbook de deploy está desatualizado

deploy.md usa uma lista manual de arquivos que não inclui vários módulos atuais como processos.js, log-visual.js/css e outros componentes. Isso permite GitHub main diferente da VM demonstrada.

**Correção preferida:** deploy por checkout de SHA ou artefato versionado, não por SCP seletivo.

---

# 5. Achados BAIXOS

## L-01 — README chama adapter de “somente leitura”, mas ele escreve

poc/README.md está defasado. O adapter possui POST, ingest de red-team e export de Evidence Bundle.

## L-02 — Monólitos elevam risco de regressão

poc/server.py e poc/dashboard/app.js concentram responsabilidades demais. Recomenda-se decomposição gradual de rotas, engine, ataques, resiliência, certificados, bridge e UI.

## L-03 — Modo contínuo pode produzir pendentes negativo

construir_conteudo() suporta CONTINUOUS_PASSOS depois do fim do roteiro, enquanto _resumo() usa len(_passos(proc)) - len(eventos). Em modo contínuo isso pode ficar negativo.

**Correção:** max(0, ...) e continuous_mode separado.

---

# 6. Deploy não totalmente auditável pelo GitHub

O repositório documenta Nginx público e stf-dashboard.service, mas as configurações efetivas de Nginx e systemd não estão versionadas.

Logo não foi possível provar, só pelo repositório:

- headers encaminhados;
- comportamento real de Host/Origin;
- TLS/CSP/security headers;
- cache;
- timeouts;
- limites de body no proxy;
- usuário e privileges do serviço;
- sandboxing systemd.

X-STF-POC: 1 é proteção contextual/anti-CSRF, **não autenticação**. O valor está no próprio JavaScript público e não é segredo.

---

# 7. Revisão da afirmação jurídica de indisponibilidade

Fonte oficial: Lei 11.419/2006, art. 10, §2º  
https://www.planalto.gov.br/ccivil_03/_ato2004-2006/2006/lei/l11419.htm

A lei prevê prorrogação automática no contexto legal quando o sistema do Poder Judiciário se torna indisponível por motivo técnico.

A regulamentação do PJe pelo CNJ também possui regras de aferição, relatório/certidão e prorrogação:  
https://atos.cnj.jus.br/atos/detalhar/1933

Conclusão para a POC: a regra jurídica existe, mas a POC não pode atribuir efeito oficial à própria certidão sintética.

---

# 8. Fortalezas confirmadas

Foram revalidados: loopback do servidor/core, recusa de host remoto pelo adapter, redirects bloqueados, limites nas superfícies JSON, body HTTP limitado, controle contextual de mutações, idempotência de telemetria, policy fail-closed, action/identity/parameter binding, anti-replay, expiry de approval, upstream oracle no harness, tamper modify/delete/reorder/truncate, hashes inválidos convertidos em FAIL, snapshot concorrente, negative controls, DATA_ONLY/tools_allowed=false, detector-MISS, caso Moraes sintético, preservação dos bytes originais, HTTP smoke e 119 testes verdes.

---

# 9. O que o CI verde prova e o que não prova

### Prova hoje

~~~text
Python compile                     PASS
119 unit tests                     PASS
HTTP smoke                         PASS
JavaScript syntax                  PASS
~~~

### Não prova hoje

~~~text
persistência real em falha         NOT TESTED
append failover continuity         NOT TESTED
DOM/tab integration                NOT TESTED
Nginx config                       NOT VERSIONED
systemd hardening                  NOT VERSIONED
SBOM                               NOT GENERATED
dependency vulnerability scan      NOT RUN
mutation qualification             NOT IMPLEMENTED
WORM/HSM/TSA external trust        NOT CONFIGURED
real PDF parser qualification      NOT IMPLEMENTED
institutional legal effect         NOT APPLICABLE
~~~

---

# 10. Ordem de remediação

### P0
1. H-01: nunca retornar accepted=true em falha.
2. H-02: identificar MEMORY_FALLBACK explicitamente.
3. H-03: fail closed em append ou implementar WAL/reconciliação real.
4. H-04: retirar claims absolutos e uso de “oficial”.
5. Criar testes negativos de persistência e failover de append.

### P1
6. Query inválida deve falhar explicitamente.
7. Limitar tamanho de bundle.
8. Adicionar DOM/headless tests.
9. Implementar subconjunto executável das SPEC-0015/0016.
10. Remover inline JS handlers.
11. Deploy por SHA/artefato.
12. Versionar Nginx/systemd.

### P2
13. Endurecer zera.py.
14. Decompor monólitos.
15. Corrigir documentação stale.
16. Separar métricas do roteiro e modo contínuo.

---

# 11. Gate proposto para próxima qualificação

~~~text
H-01 false persistence              FIXED + RED/GREEN TEST
H-02 provenance fallback            FIXED + UI BADGE TEST
H-03 append failover                FIXED + FAILURE INJECTION
H-04 institutional claims           FIXED + CLAIM LINT
M-01 invalid query response         FAIL CLOSED
M-02 bundle max bytes               ENFORCED
M-03 DOM integration                PASS
M-04 SPEC-0015/0016 subset          PASS
M-08 deploy by SHA                  PASS
119+ unit tests                     PASS
HTTP smoke                          PASS
JS/DOM tests                        PASS
~~~

# 12. Conclusão

O projeto está mais maduro do que na auditoria de setembro. Os controles de policy e evidência do harness evoluíram de forma consistente. O ponto fraco agora é a fronteira entre **o que realmente foi persistido/observado** e **o que o fallback ou a apresentação dizem que aconteceu**.

A prioridade técnica é impedir qualquer conversão de:

~~~text
falhou / desconhecido / RAM
~~~

em:

~~~text
persistido / íntegro / HeraclitusDB real
~~~

Depois disso, a prioridade é disciplinar claims da interface. Uma prova técnica forte não precisa afirmar que “ninguém consegue alterar”. Ela precisa declarar exatamente qual propriedade foi testada, contra qual ameaça, sob qual domínio de confiança e com qual evidência.
