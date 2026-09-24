# Estado de Implementação — POC STF / HeraclitusDB

**Atualizado:** 23/09/2026

Este documento separa capacidades realmente executadas pelo harness da POC de entradas e integrações que continuam sintéticas.

## Executado e calculado pelo código da POC

| Capacidade | Estado | Implementação |
|---|---|---|
| Telemetria heterogênea | IMPLEMENTADO | `poc/telemetry.py` normaliza edge, IAM, host, rede, DB e app |
| Preservação raw → canonical | IMPLEMENTADO | raw e resultado normalizado ficam no evento/evidência |
| Detecção | IMPLEMENTADO | `poc/detector.py`, regras determinísticas explicáveis |
| Negativos benignos das regras | TESTADO | testes comprovam que eventos abaixo do limiar não geram sinal |
| Correlação cross-source | IMPLEMENTADO | `poc/correlation.py`, componentes por entidades compartilhadas |
| Exclusão de sinal não relacionado | TESTADO | correlação não absorve sinal desconectado |
| Abertura de incidente | IMPLEMENTADO | depende do componente correlacionado qualificado |
| Policy enforcement | IMPLEMENTADO | `poc/policy.py`, fail-closed |
| HITL | IMPLEMENTADO NA POC | approval vinculada, single-use |
| Anti-replay | IMPLEMENTADO | approval consumida não executa de novo |
| Identity & Action binding | IMPLEMENTADO | identidade ou ação divergente gera DENY (`IDENTITY_BINDING_MISMATCH`, `ACTION_BINDING_MISMATCH`) |
| Parameter/target binding | IMPLEMENTADO | alvo/digest diferente gera DENY (`PARAMETERS_DIGEST_MISMATCH`) |
| Independent upstream oracle | IMPLEMENTADO | `poc/synthetic_upstream.py` emite recibos (`EFF-xxxxxx`) com digest canônico; `upstream_hits` e `upstream_delta=0` em DENY estritamente verificados |
| Hash-chain | IMPLEMENTADO NO HARNESS | SHA-256 entre eventos da POC |
| Merkle root | IMPLEMENTADO NO HARNESS | raiz sobre hashes dos eventos |
| Tamper modify/delete/reorder/truncate | IMPLEMENTADO | cópia adulterada falha na verificação |
| Time travel AS-OF | IMPLEMENTADO NO HARNESS | reconstrução determinística por LSN com replay de recibos |
| Evidence Bundle | IMPLEMENTADO NO HARNESS | pacote JSON com eventos, signals, incidente, grafo e qualification |
| Offline verifier | IMPLEMENTADO | `poc/verify.py` independente do servidor e com isolamento temporário |
| Adapter & Surface Health | IMPLEMENTADO | `poc/heraclitus_adapter.py` monitora status `CONNECTED`, `DEGRADED` e `UNAVAILABLE` |
| Dashboard & Guided Journey | IMPLEMENTADO | modo guiado narrativo ("Acompanhe a Campanha"), Journey Map em 8 estágios, replay, WHY, graph, policy, forensic diff, evidence inspector |
| HTTP smoke | IMPLEMENTADO | CI sobe servidor loopback e valida endpoints e proteções CSRF |

## Sintético por desenho

Os itens abaixo **não representam acesso ou execução contra infraestrutura do STF**:

- o agente atacante;
- tráfego de firewall/WAF;
- identidades e sessões;
- hosts Windows/Linux;
- movimento lateral;
- banco transacional;
- aplicação judicial;
- processos e documentos;
- endereços de rede;
- credenciais;
- approvals humanas;
- ações de contenção.

Os nomes usados são fictícios ou reservados para documentação.

## Implementação local da POC versus HeraclitusDB real

O harness possui hash-chain, Merkle, correlação e policy próprios para tornar a demonstração standalone e reproduzível.

Isso **não significa** que esses componentes substituam os crates reais do HeraclitusDB.

Quando um HeraclitusDB real estiver disponível em loopback, o bridge read-only pode consultar superfícies já confirmadas no código do projeto:

- `/sentinel/status`;
- `/sentinel/incidents`;
- `/sentinel/incidents/:id`;
- `/sentinel/incidents/:id/evidence`;
- `/sentinel/incidents/:id/why`;
- `/sentinel/actions`;
- `/sentinel/dashboard`;
- `/telemetry/health`;
- `/compliance/status`;
- `/api/v1/agent/status`;
- `/api/v1/agent/red-team/events`.

A evolução natural é substituir progressivamente os equivalentes standalone pelos resultados do runtime real, mantendo o dashboard e a suíte de qualificação.

## Não configurado / não alegar como concluído

- integração com logs reais do STF;
- firewall/WAF/IAM/EDR reais;
- banco ou aplicação real;
- HSM/KMS institucional;
- trust anchors do STF;
- assinatura institucional;
- timestamp externo institucional;
- ICP-Brasil validada no ambiente do órgão;
- operação HA/DR do piloto;
- resposta automática em rede real;
- certificação, homologação ou endorsement pelo STF.

## Regra de claim

Uma demonstração pode afirmar:

> A POC executa e verifica a cadeia lógica completa em ambiente sintético e fornece pontos de integração read-only para um HeraclitusDB local.

Ela não deve afirmar:

> O HeraclitusDB está integrado à infraestrutura do STF ou detectará qualquer invasão real.

A segunda frase exige piloto, telemetria, integrações e validação institucional.
