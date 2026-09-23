# Checklist da Reunião Técnica — POC Integrada

## Demonstração

Levar:

- ambiente offline;
- campaign run limpa;
- scorecard Fase 1/Fase 2;
- grafo do incidente;
- Evidence Bundle válido;
- bundle adulterado;
- hashes/build info;
- baseline público e técnico.

## Mensagem em 30 segundos

> A POC simula uma campanha de ataque em ambiente isolado. O HeraclitusDB recebe telemetria de múltiplas classes, correlaciona o incidente e preserva provenance. O mesmo contexto de comprometimento alimenta a política que governa tentativas posteriores de alteração em aplicação e banco fictícios. No final, toda a campanha é exportada e verificada offline.

## Perguntas de discovery para o STF

Sem pedir detalhes sensíveis:

1. Quais **classes** de telemetria seriam prioritárias em eventual piloto: rede, identidade, host, banco ou aplicação?
2. Existe preferência por Syslog, API, fila ou collector para integração futura?
3. O primeiro caso de uso deveria priorizar SOC, auditoria de banco, aplicações judiciais ou agentes de IA?
4. Quais resultados seriam considerados suficientes para uma POC aprovada?
5. Em eventual piloto, qual equipe seria dona do incidente e qual equipe seria dona da evidência?
6. Quais integrações devem permanecer somente read-only?
7. Que mecanismos institucionais de IAM/KMS/HSM deveriam ser avaliados numa fase posterior?
8. Qual ferramenta corporativa deve receber alertas, sem pedir credenciais ou arquitetura na primeira reunião?

## Não pedir

- IP;
- hostname;
- regra de firewall;
- versão de appliance;
- vulnerabilidade;
- credencial;
- dump;
- log real sigiloso;
- acesso à rede;
- dados processuais reais.

A primeira POC deve ser convincente sem nada disso.
