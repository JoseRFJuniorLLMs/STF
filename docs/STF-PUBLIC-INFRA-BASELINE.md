# Baseline Público de Ambiente Tecnológico do STF

**Data da pesquisa:** 23/09/2026

Este documento serve exclusivamente para tornar a POC arquiteturalmente plausível. Ele não é inventário de segurança e deliberadamente não registra IPs, endereços internos, versões vulneráveis, regras de firewall ou topologia fina.

## 1. Sistemas e serviços publicamente confirmados

### STF Digital / sistemas judiciais

O STF publica que ferramentas de IA e funcionalidades jurisdicionais estão integradas ao **STF Digital**, ambiente que centraliza sistemas eletrônicos da Corte.

Fontes:
- https://noticias.stf.jus.br/postsnoticias/stf-amplia-uso-de-inteligencia-artificial-em-apoio-a-atividade-jurisdicional/
- https://portal.stf.jus.br/noticias/verNoticiaDetalhe.asp?idConteudo=508710&ori=1

### Processo eletrônico e peticionamento

A Resolução STF 693/2020 disciplina sistemas oficiais para tramitação, transmissão e comunicação de atos processuais.

Fonte:
- https://portal.stf.jus.br/textos/verTexto.asp?servico=processoResolucao

### MNI

O STF usa o Modelo Nacional de Interoperabilidade para troca automatizada de processos e peças com outros tribunais e órgãos.

Fonte:
- https://portal.stf.jus.br/textos/verTexto.asp?pagina=mni&servico=processoIntegracaoInformacaoGeral

### SEI

O STF mantém SEI interno/externo para processos e documentos administrativos.

Fonte:
- https://portal.stf.jus.br/textos/verTexto.asp?pagina=sistemasei&servico=sobreStfAcervoArquivo

## 2. Data center e infraestrutura física

Há contratação pública de suporte 24x7 para centros de dados do STF e estruturas de sala-cofre/sala segura.

Fonte:
- Pregão 90062/2024, Compras.gov.br.

Em 2026 o STF anunciou manutenção preventiva da infraestrutura de TI com indisponibilidade coordenada de SEI, peticionamento, portal, sistemas corporativos e MNI.

Fonte:
- https://noticias.stf.jus.br/postsnoticias/sistemas-do-stf-ficarao-temporariamente-indisponiveis-no-domingo-19/

## 3. Computação, Linux e IA

### HPC

Em 2025 houve registro de preços para equipamentos servidores de computação de alto desempenho.

Fonte:
- Portal de Licitações STF, Pregão 90016/2025.

### Linux

Há histórico recente de ferramentas self-hosted em Linux e, em 2026, o STF aparece como participante de ata para solução SUSE Linux Enterprise Server / suporte Multi-Linux / SUSE Manager.

Fontes:
- Pregão 17/2023 — JFrog Enterprise X em Linux;
- PNCP Ata 00001/2026 — solução integrada SUSE.

### IA local

Em setembro de 2025, o STF informou investimento em infraestrutura própria para IA e implantação de modelos de linguagem de código aberto em servidores destinados ao data center da Corte.

Fonte:
- https://noticias.stf.jus.br/postsnoticias/stf-amplia-uso-de-inteligencia-artificial-em-apoio-a-atividade-jurisdicional/

Ferramentas publicamente citadas incluem Victor, Rafa, VitórIA e Maria.

## 4. Dados e analytics

Em proposta administrativa publicada em 2026, a estrutura de TI/IA é associada à criação/manutenção de bases para painéis e análise, incluindo:

- data warehouse;
- data lake;
- data marts.

Também há contratações públicas de:

- Microsoft Power BI Professional;
- SAP BusinessObjects.

Fontes:
- PADM 1/DF, proposta de estrutura de STI/NIAC;
- Portal de Licitações STF 2025.

## 5. Rede e acesso de usuário

### LAN/WLAN

Em 2025 houve contratação para solução de interconexão de redes LAN e WLAN com equipamentos e gerência.

Fonte:
- Portal de Licitações STF, Pregão 90025/2025.

### VDI

Em 2026 foi publicado pregão para infraestrutura de desktops virtuais com Omnissa Horizon 8 Enterprise e Microsoft Windows 11 Enterprise VDA.

Fonte:
- Compras.gov.br, Pregão 90007/2026.

## 6. Proteção de dados e backup

Em 2025 foi publicada contratação para solução de proteção de dados do tipo appliance, com equipamentos, software, implantação, suporte e garantia.

Fonte:
- Compras.gov.br, Pregão 90029/2025.

Há histórico mais antigo de uso de NetBackup e Oracle no STF, mas **a POC não presume que esses sejam os produtos transacionais atuais**.

## 7. Desenvolvimento e colaboração

Há evidência pública de ferramentas como:

- JFrog Artifactory/Xray self-hosted;
- Sourcegraph Enterprise Search;
- OnlyOffice Docs Enterprise self-hosted;
- Atlassian Cloud em contratação em 2026.

Essas classes reforçam que a POC pode incluir telemetria de supply-chain/dev tooling como fonte opcional, sem assumir detalhes internos.

## 8. Perfil sintético adotado na POC

```text
PUBLIC EDGE
  -> FW/WAF Adapter [vendor-neutral]

IDENTITY
  -> IAM Adapter [vendor-neutral]

NETWORK
  -> LAN/WLAN / DNS / Proxy synthetic telemetry

COMPUTE
  -> Linux + Windows synthetic hosts
  -> HPC/AI node class

APPLICATION
  -> STF-Digital-like synthetic judicial app
  -> SEI-like synthetic admin app
  -> MNI-like integration service

DATA
  -> transactional DB audit [engine-neutral]
  -> data lake / warehouse event source

AI
  -> synthetic assistant/agent

BACKUP
  -> protection/backup audit source
```

## 9. O que deliberadamente permanece genérico

Sem confirmação pública atual suficiente, a POC não fixa:

- fabricante de firewall;
- WAF;
- SIEM;
- EDR;
- banco transacional principal;
- diretório/IAM interno;
- hypervisor atual;
- storage primário;
- segmentação real;
- versões internas.

Esses campos viram adapters configuráveis.
