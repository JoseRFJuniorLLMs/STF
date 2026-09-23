# STF — POC HeraclitusDB

> **Repositório independente de prova de conceito.** Este projeto não é produto oficial, homologado, certificado ou endossado pelo Supremo Tribunal Federal. A POC usa exclusivamente dados sintéticos e existe para avaliação técnica de mecanismos de integridade, evidência, auditoria e governança de agentes de IA.

## Objetivo

Demonstrar, de forma reproduzível e verificável, que uma camada de confiança baseada no HeraclitusDB pode:

- preservar eventos em histórico append-only;
- detectar adulteração, exclusão e reordenação de registros;
- reconstruir estados históricos;
- governar ações sensíveis de agentes de IA;
- exigir aprovação humana para operações classificadas;
- bloquear replay, autorização expirada e troca indevida de identidade;
- exportar um pacote de evidências;
- permitir verificação independente e offline das propriedades locais da prova;
- operar sem integração com sistemas reais do STF na fase de POC.

A pergunta central da demonstração é:

> **Se um sistema, operador ou agente de IA executar uma operação sensível, conseguimos provar exatamente o que aconteceu, detectar adulteração posterior e impedir ações não autorizadas?**

## Escopo da POC

A POC não substitui PJe, bancos corporativos, SIEM, IAM ou sistemas administrativos. Ela simula uma integração lateral, com dados sintéticos, para validar propriedades de segurança e auditabilidade antes de qualquer discussão de piloto institucional.

```text
Aplicação simulada ──┐
Agente de IA ────────┼──> HeraclitusDB ──> Evidência ──> Verificador offline
Eventos de segurança ┘          |
                                +──> Policy / HITL / Anti-Replay
```

## SPECs

| SPEC | Título | Finalidade |
|---|---|---|
| [SPEC-0001](specs/SPEC-0001-scope-success-criteria.md) | Escopo e critérios de sucesso | Define o que a POC deve e não deve provar |
| [SPEC-0002](specs/SPEC-0002-reference-architecture.md) | Arquitetura de referência | Define fronteiras, componentes e integrações |
| [SPEC-0003](specs/SPEC-0003-synthetic-event-model.md) | Modelo de eventos sintéticos | Define dados, identidades e cenários |
| [SPEC-0004](specs/SPEC-0004-integrity-tamper-detection.md) | Integridade e adulteração | Define provas de imutabilidade e detecção |
| [SPEC-0005](specs/SPEC-0005-agent-governance-hitl.md) | Governança de agentes e HITL | Define políticas e aprovação humana |
| [SPEC-0006](specs/SPEC-0006-adversarial-security-tests.md) | Testes adversariais | Define replay, bypass, expiração e identidade |
| [SPEC-0007](specs/SPEC-0007-evidence-bundle-offline-verifier.md) | Evidence Bundle e verificador offline | Define exportação e verificação independente |
| [SPEC-0008](specs/SPEC-0008-temporal-reconstruction.md) | Reconstrução temporal | Define consultas e replay histórico |
| [SPEC-0009](specs/SPEC-0009-reproducible-airgap-deployment.md) | Implantação reproduzível e air-gap | Define execução isolada e cadeia de build |
| [SPEC-0010](specs/SPEC-0010-demo-runbook.md) | Runbook da demonstração | Define roteiro executável de 30–45 minutos |
| [SPEC-0011](specs/SPEC-0011-observability-performance.md) | Observabilidade e desempenho | Define métricas mínimas da POC |
| [SPEC-0012](specs/SPEC-0012-governance-privacy-pilot-transition.md) | Governança, privacidade e transição para piloto | Define limites jurídicos/técnicos e próximos gates |

## Princípios

1. **Dados sintéticos apenas.**
2. **Sem acesso ao ambiente produtivo do STF.**
3. **Sem afirmações de homologação, certificação ou conformidade institucional.**
4. **Falha explícita é melhor que sucesso presumido.**
5. **Ausência de âncora externa de confiança nunca pode aparecer como PASS.**
6. **Toda afirmação demonstrada deve ter evidência reproduzível.**
7. **A POC deve ser executável por terceiro a partir de instruções versionadas.**
8. **O verificador deve funcionar sem confiar no processo que produziu a evidência.**

## Relação com o HeraclitusDB

A POC reutiliza capacidades atuais do HeraclitusDB quando disponíveis e cria adaptadores experimentais apenas onde necessário. Recursos que no projeto principal ainda estejam marcados como `Draft`, `Proposed` ou `roadmap` continuam com essa classificação aqui.

Em particular, o pacote forense completo e o protocolo de administração confiável possuem SPECs próprias no HeraclitusDB e não devem ser apresentados como recursos de produção antes de seus gates correspondentes.

## Resultado esperado

Ao final da POC, um avaliador independente deve conseguir executar cenários positivos e negativos e obter resultados objetivos como:

```text
APPEND HISTORY             PASS
TAMPER DETECTION           PASS
DELETE DETECTION           PASS
REORDER DETECTION          PASS
TIME TRAVEL                PASS
UNAPPROVED ACTION          DENY
REPLAYED APPROVAL          DENY
EXPIRED APPROVAL           DENY
IDENTITY MISMATCH          DENY
EVIDENCE EXPORT            PASS
OFFLINE LOCAL VERIFY       PASS
EXTERNAL TIMESTAMP         NOT CONFIGURED
INSTITUTIONAL SIGNATURE    NOT CONFIGURED
```

A POC é considerada tecnicamente concluída somente quando os critérios da SPEC-0001 e o runbook da SPEC-0010 puderem ser reproduzidos em ambiente limpo.
