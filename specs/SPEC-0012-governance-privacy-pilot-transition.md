# SPEC-0012 — Governança, Privacidade e Transição de POC para Piloto

**Status:** Proposed  
**Classe:** Governance / Privacy / Pilot Gate  
**Prioridade:** P1  
**Dependências:** SPEC-0001 a SPEC-0011

## 1. Objetivo

Impedir que uma POC bem-sucedida seja confundida com autorização para produção. A passagem para piloto exige novo gate técnico e institucional.

## 2. Identidade do projeto

Este repositório deve manter aviso visível:

- projeto independente;
- não oficial do STF;
- não homologado;
- não certificado;
- sem dados reais;
- sem endosso institucional implícito.

## 3. Privacidade

A POC usa exclusivamente:

- nomes fictícios;
- IDs sintéticos;
- documentos artificiais;
- secrets efêmeros.

Qualquer dado real encontrado deve bloquear publicação do artefato afetado até saneamento.

## 4. Compliance

A POC pode mapear controles técnicos para normas, políticas e requisitos institucionais, mas esse mapeamento deve usar estados:

```text
PASS
FAIL
PARTIAL
EXTERNAL
NOT_APPLICABLE
NOT_ASSESSED
UNKNOWN
```

Nenhum dashboard deve exibir “COMPLIANT=true”.

## 5. Dependências externas de confiança

Itens que exigem decisão/infraestrutura institucional:

- trust anchors;
- ACT;
- HSM/KMS;
- IAM;
- certificados;
- política de retenção;
- WORM;
- SIEM;
- segmentação;
- backup/DR;
- gestão de vulnerabilidade.

Na POC permanecem EXTERNAL ou NOT_CONFIGURED.

## 6. Gate para piloto

Antes de qualquer piloto com ambiente ou dados institucionais, criar documento específico contendo:

1. patrocinador e responsáveis;
2. escopo;
3. classificação dos dados;
4. arquitetura aprovada;
5. threat model atualizado;
6. DPIA/avaliação de privacidade quando aplicável;
7. IAM;
8. secrets;
9. backup;
10. observabilidade;
11. plano de rollback;
12. critérios de encerramento;
13. tratamento de incidentes;
14. responsabilidade por operação;
15. licenciamento e propriedade intelectual.

## 7. Critério de promoção

POC => PILOT somente se:

- P0 completo;
- limitações aceitas;
- riscos documentados;
- responsáveis definidos;
- ambiente piloto separado;
- dados autorizados;
- integrações aprovadas.

## 8. Critério de não promoção

A POC não deve avançar se a única justificativa for “a demo funcionou”.

Funcionamento é condição necessária. Não é governança.

## 9. Entregáveis ao final da POC

- código;
- SPECs;
- hashes;
- SBOM disponível;
- relatório dos testes;
- Evidence Bundle de exemplo;
- saída do verificador;
- lista de limitações;
- matriz de riscos;
- proposta de arquitetura de piloto, apenas se solicitada.

## 10. Encerramento

A mensagem técnica da POC deve permanecer:

> A solução deve produzir evidências verificáveis e controles testáveis, em vez de exigir confiança cega no próprio sistema que está sendo auditado.
