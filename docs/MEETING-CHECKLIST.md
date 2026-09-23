# Checklist da Reunião Técnica — Segurança da Informação / STF

## O que levar

- notebook/VM com POC offline;
- kit local com hashes;
- diagrama de arquitetura;
- threat model;
- scorecard;
- Evidence Bundle válido;
- Evidence Bundle adulterado;
- README/SPECs disponíveis localmente;
- commit exato dos repositórios.

## Perguntas de discovery

Estas perguntas são para eventual fase posterior, não pré-requisitos para a demo.

### Arquitetura

1. O STF prefere avaliação em VM, containers ou infraestrutura específica?
2. Há restrições para execução de Rust/binários de laboratório?
3. O primeiro caso de uso desejado seria segurança/SOC, auditoria de IA, cadeia de custódia ou outro?
4. O piloto deveria receber eventos por API, fila, arquivo ou collector existente?

### Segurança

5. Qual mecanismo institucional de identidade seria considerado para service-to-service?
6. Há HSM/KMS que deveria ser alvo de uma etapa futura?
7. Qual SIEM/observability é usado para integrar alertas e métricas?
8. Qual política de segmentação/egress deve ser respeitada?

### Evidência

9. Há preferência por formato de pacote e relatório técnico?
10. Quais metadados de cadeia de custódia seriam considerados mínimos?
11. Existe infraestrutura institucional de carimbo de tempo/ICP-Brasil a ser testada posteriormente?
12. Há storage com retenção/WORM disponível?

### Operação

13. Qual equipe avaliaria o código e qualification report?
14. Quais critérios fariam o STF considerar a POC tecnicamente bem-sucedida?
15. Qual seria o menor escopo aceitável para um piloto isolado?
16. Que informação **não** deve entrar na POC/piloto sob nenhuma hipótese?

## O que não pedir na primeira reunião

- acesso a PJe;
- credenciais;
- dados reais;
- acesso à rede interna;
- chaves;
- exceção de firewall.

Primeiro demonstrar propriedade técnica com dados sintéticos. Depois discutir qualquer integração.

## Mensagem de encerramento

A pergunta não é “vocês confiam no HeraclitusDB?”. A pergunta é:

> Quais propriedades o STF gostaria de verificar de forma independente antes de confiar em uma camada desse tipo?
