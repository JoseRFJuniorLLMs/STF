# SPEC-0020 — Risk Register e Pilot Readiness

**Status:** Proposed  
**Classe:** Risk / Decision Support  
**Prioridade:** P1  
**Dependências:** SPEC-0012, SPEC-0013

## 1. Objetivo

Converter resultados da POC em perguntas objetivas para eventual piloto, sem transformar sucesso técnico em autorização implícita.

## 2. Registro de risco

Campos: risk_id, asset, scenario, likelihood qualitativa, impact qualitativo, controls, residual risk, evidence, owner, treatment e target phase.

## 3. Riscos mínimos

- bypass do gateway por topologia;
- comprometimento de chave;
- falso senso de confiança em timestamp;
- retenção inadequada;
- acesso excessivo;
- dependência de terceiro;
- vulnerabilidade de supply chain;
- falha de policy update;
- crescimento de storage;
- indisponibilidade;
- integração legada;
- erro operacional.

## 4. Pilot readiness

| Domínio | POC | Piloto exige |
|---|---|---|
| dados | sintéticos | classificação/autorização |
| IAM | sintético | identidade institucional |
| crypto | laboratório | trust/KMS/HSM |
| rede | isolada | arquitetura aprovada |
| observabilidade | local | integração corporativa |
| retenção | curta | política institucional |
| DR | fora de escopo | RPO/RTO |
| operação | desenvolvedor | owner/runbook/SLA |
| segurança | threat model POC | avaliação institucional |

## 5. Estados

- NOT_READY;
- READY_FOR_SCOPED_PILOT;
- READY_WITH_CONDITIONS.

A decisão final é institucional. A ferramenta apenas apresenta evidências e dependências.

## 6. Perguntas para etapa posterior

Qual primeiro produtor de eventos? Qual dado pode entrar? Qual identidade aprova? Qual storage de retenção existe? Há HSM/KMS? Qual SIEM recebe eventos? Quem opera? Quais critérios encerram o piloto?
