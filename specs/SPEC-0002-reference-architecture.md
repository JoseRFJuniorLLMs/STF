# SPEC-0002 — Arquitetura de Referência e Fronteiras de Integração

**Status:** Proposed  
**Classe:** Architecture / Integration  
**Prioridade:** P0  
**Dependências:** SPEC-0001

## 1. Princípio

A POC trata o HeraclitusDB como camada lateral de confiança, não como substituto de sistemas existentes.

```text
Aplicação simulada ───────┐
Eventos de segurança ─────┼────> Adapter ───> HeraclitusDB
Agente / MCP ─────────────┘                     |
                                                +--> HRKL / histórico
                                                +--> políticas
                                                +--> evidência
                                                +--> consultas temporais
                                                |
                                                v
                                         Evidence Exporter
                                                |
                                                v
                                         Offline Verifier
```

## 2. Componentes

### 2.1 Producer Simulator

Gera eventos sintéticos equivalentes a:

- autenticação;
- consulta;
- acesso a documento;
- classificação;
- solicitação de ação;
- aprovação;
- execução;
- erro;
- exportação.

Não simula semântica jurídica real.

### 2.2 POC Adapter

Responsável por transformar eventos sintéticos para o envelope canônico da SPEC-0003.

O adapter MUST:

- não alterar payload sem registrar transformação;
- preservar identidade de origem;
- calcular digest do payload;
- atribuir correlation_id;
- rejeitar evento sem campos obrigatórios.

### 2.3 HeraclitusDB

A POC deve usar apenas capacidades identificadas como existentes no baseline do projeto principal. Recursos de roadmap podem ser implementados localmente como protótipos POC, mas devem ser marcados como experimentais.

### 2.4 Agent Gateway

Intercepta operações do agente antes do efeito externo.

Modos:

- observe: registra sem bloquear;
- shadow: calcula decisão, mas não bloqueia;
- enforce: decisão negativa impede execução.

A demonstração P0 utiliza enforce para ações sensíveis.

### 2.5 Evidence Exporter

Produz pacote autocontido conforme SPEC-0007.

### 2.6 Offline Verifier

Processo separado do exporter. Idealmente binário ou comando independente, executável sem acesso de rede.

## 3. Fronteiras de confiança

```text
[UNTRUSTED INPUT]
  producer / agent / user input
          |
          v
[VALIDATION BOUNDARY]
          |
          v
[HERACLITUS TRUST DOMAIN]
          |
          +--> persistent history
          +--> policy decision
          +--> evidence
          |
          v
[EXPORT BOUNDARY]
          |
          v
[INDEPENDENT VERIFIER]
```

O verificador não deve assumir que o exporter é honesto. Ele valida estrutura, digests e provas disponíveis.

## 4. Princípios de falha

- erro de validação de evento => REJECT;
- falta de aprovação exigida => DENY;
- aprovação inválida => DENY;
- falha na persistência crítica => operação sensível não deve ser reportada como PASS;
- confiança externa ausente => UNVERIFIED ou NOT_CONFIGURED;
- resultado desconhecido após falha => UNKNOWN, nunca sucesso inventado.

## 5. Topologia da POC

Execução recomendada:

```text
poc-network
├── producer
├── heraclitus
├── agent-gateway
├── demo-upstream
└── exporter

offline-verifier
└── executado fora de poc-network no teste final
```

## 6. Segurança de rede

Na POC:

- serviços devem escutar apenas onde necessário;
- portas publicadas devem ser documentadas;
- nenhuma credencial real pode existir;
- acesso de saída deve ser desnecessário para os testes principais;
- verificação offline deve funcionar com rede desabilitada.

## 7. Não objetivos

Esta arquitetura não pretende provar:

- HA de produção;
- DR institucional;
- dimensionamento para carga do STF;
- compatibilidade com PJe;
- federação de identidade real;
- HSM real;
- ACT real;
- operação multi-datacenter.

Esses itens pertencem a eventual piloto posterior.
