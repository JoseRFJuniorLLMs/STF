# SPEC-0001 — Escopo, Hipóteses e Critérios de Sucesso

**Status:** Proposed  
**Classe:** POC Governance / Acceptance  
**Prioridade:** P0  
**Dependências:** nenhuma  
**Baseline técnico:** HeraclitusDB conforme estado do repositório principal em 23/09/2026.

## 1. Objetivo

Esta SPEC define o contrato de sucesso da POC HeraclitusDB para avaliação técnica relacionada ao STF. A POC deve provar propriedades técnicas observáveis, sem afirmar homologação, certificação, conformidade institucional, admissibilidade jurídica automática ou aptidão para produção.

A POC deve responder:

> Se um sistema, operador ou agente de IA realizar uma operação sensível, é possível preservar sua história, controlar a execução, detectar adulteração posterior e produzir evidência verificável de forma independente?

## 2. Fora de escopo

Nesta fase é proibido depender de:

- dados processuais reais;
- credenciais reais do STF;
- integração com PJe ou sistemas internos;
- chaves institucionais reais;
- ACT/ICP-Brasil real como requisito para concluir a POC;
- ambiente de produção;
- promessa de substituição de banco de dados corporativo;
- promessa de conformidade apenas porque um controle técnico existe.

## 3. Hipóteses

A POC opera com:

- dados sintéticos;
- identidades sintéticas;
- aplicação simulada;
- agente de IA simulado ou controlado;
- políticas versionadas;
- ambiente isolado;
- build identificável;
- logs e artefatos preservados.

## 4. Critérios obrigatórios

| ID | Propriedade | Teste | Resultado exigido |
|---|---|---|---|
| AC-01 | append-only | inserir sequência válida | PASS |
| AC-02 | adulteração | alterar bytes/evento preservado | DETECTED |
| AC-03 | exclusão | remover evento preservado | DETECTED |
| AC-04 | reordenação | trocar ordem de eventos | DETECTED |
| AC-05 | replay histórico | reconstruir estado em ponto anterior | PASS |
| AC-06 | ação sensível | executar sem aprovação | DENY |
| AC-07 | HITL | executar com aprovação válida | PASS |
| AC-08 | replay de aprovação | reutilizar aprovação consumida | DENY |
| AC-09 | expiração | usar aprovação expirada | DENY |
| AC-10 | identidade | usar aprovação de outra identidade | DENY |
| AC-11 | exportação | gerar Evidence Bundle | PASS |
| AC-12 | verificação | verificar bundle sem banco de origem | PASS |
| AC-13 | sabotagem do bundle | modificar objeto após exportação | DETECTED |
| AC-14 | confiança externa ausente | sem TSA/chave institucional | NOT CONFIGURED ou UNVERIFIED |
| AC-15 | execução limpa | reproduzir POC em ambiente novo | PASS |

## 5. Regra de não ambiguidade

Nenhum teste pode terminar apenas com texto narrativo como “aparentemente íntegro” ou “executado com sucesso”. A saída deve ser máquina-legível e conter um status canônico:

```text
PASS
FAIL
DENY
DETECTED
PARTIAL
UNVERIFIED
NOT_CONFIGURED
NOT_APPLICABLE
```

## 6. Definition of Done

A POC só pode ser declarada concluída quando:

1. todos os testes P0 tiverem script reproduzível;
2. os cenários negativos forem executados, não apenas descritos;
3. a adulteração for detectada após sabotagem intencional;
4. o verificador funcionar sem consultar o banco original;
5. hashes dos artefatos de build estiverem publicados no resultado;
6. limitações forem impressas no relatório;
7. um terceiro conseguir seguir a SPEC-0010 sem conhecimento interno do desenvolvimento.

## 7. Resultado proibido

A conclusão nunca deve ser “HeraclitusDB é seguro” ou “HeraclitusDB está homologado para o STF”.

A conclusão permitida é limitada às propriedades efetivamente testadas, por exemplo:

> Nesta configuração de POC, os cenários definidos AC-01 a AC-15 foram executados e produziram os resultados registrados, sob as limitações documentadas.


---

## 8. Revisão de rigor — gates de qualificação

A POC passa a ter três classes de gate:

### P0 — obrigatório para a reunião técnica

- histórico válido persistido e verificável;
- modificação, exclusão e reordenação detectadas;
- ação HIGH sem aprovação não alcança o upstream;
- replay, expiração e troca de identidade bloqueados;
- Evidence Bundle verificável sem o banco de origem;
- adulteração do bundle invalida a verificação;
- execução limpa reproduzível;
- caminho crítico sem dependência externa;
- limitações de confiança externa explícitas.

### P1 — obrigatório antes de qualquer piloto

Fault injection, restart/recovery, build provenance, SBOM, hardening, limites de recursos, threat model, matriz de riscos, contrato de integração, retenção, secrets e identidade real.

### P2 — qualificação institucional posterior

HSM/KMS, ACT/ICP-Brasil real, IAM institucional, WORM externo, HA/DR, carga representativa, integrações reais e observabilidade corporativa.

## 9. Critérios adicionais de aceite

| ID | Propriedade | Teste | Resultado exigido |
|---|---|---|---|
| AC-16 | determinismo lógico | replay do mesmo dataset | mesmo state digest |
| AC-17 | fail-closed | policy store indisponível em ação HIGH | DENY |
| AC-18 | atomicidade | duas execuções com mesmo approval | upstream hits <= 1 |
| AC-19 | TOCTOU | parâmetros mudam após aprovação | DENY |
| AC-20 | isolamento | agente tenta upstream direto | BLOCKED |
| AC-21 | pacote incompleto | remover objeto | FAIL |
| AC-22 | traversal | path fora do pacote | FAIL |
| AC-23 | oversized input | request excede teto | REJECT |
| AC-24 | crash | queda durante operação crítica | nunca sucesso inventado |
| AC-25 | build identity | bundle identifica build/commit | PASS |
| AC-26 | egress | caminho P0 isolado | zero egress não declarado |
| AC-27 | segredo | varredura de artefatos | zero segredo real |
| AC-28 | verifier | exporter/origem desligados | PASS local |
| AC-29 | confiança externa | ausência de trust externo | nunca PASS externo |
| AC-30 | rastreabilidade | teste aponta evidência | PASS |

## 10. Registro mínimo por teste

Todo teste produz `run_id`, `test_id`, commits, expected, observed, reason_code, timestamps, correlation_id, evidence_refs, environment_digest e result.

`result=PASS` significa somente que o resultado observado corresponde ao esperado.

## 11. Exit codes

- 0: checks solicitados passaram;
- 2: falha de critério/verificação;
- 3: entrada inválida;
- 4: dependência obrigatória indisponível;
- 5: estado UNKNOWN que exige investigação.

A CLI nunca retorna 0 com teste falho apenas porque terminou de executar.
