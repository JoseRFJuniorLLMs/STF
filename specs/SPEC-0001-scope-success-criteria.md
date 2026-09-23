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
