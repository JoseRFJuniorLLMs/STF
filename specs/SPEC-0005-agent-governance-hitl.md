# SPEC-0005 — Governança de Agentes, Policy Gate e Human-in-the-Loop

**Status:** Proposed  
**Classe:** AI Security / Agent Governance  
**Prioridade:** P0  
**Dependências:** SPEC-0002, SPEC-0003

## 1. Objetivo

Demonstrar que a capacidade de um agente não equivale à autorização para executar uma ação.

Toda ferramenta da POC recebe uma classificação:

```text
LOW       execução automática permitida
MEDIUM    política contextual
HIGH      aprovação humana obrigatória
BLOCKED   proibida na POC
```

## 2. Ferramentas sintéticas

| Tool | Risco | Política |
|---|---:|---|
| search_public_metadata | LOW | ALLOW |
| read_internal_document | MEDIUM | ALLOW com identidade válida |
| export_restricted_document | HIGH | HITL obrigatório |
| change_classification | HIGH | HITL obrigatório |
| delete_evidence | BLOCKED | DENY sempre |

## 3. Fluxo

```text
Agent Request
    |
    v
Normalize
    |
    v
Identity Binding
    |
    v
Policy Evaluation
    |
    +--> ALLOW ------> Execute
    |
    +--> DENY -------> Record denial
    |
    +--> REQUIRE_HITL
              |
              v
         Approval Request
              |
         approve/reject
              |
              v
        Re-evaluate binding
              |
              v
           Execute
```

## 4. Approval Object

A aprovação deve ligar-se a:

- approval_id;
- request_id;
- actor/agente;
- tool;
- target/resource;
- parameters_digest;
- policy_version;
- issued_at;
- expires_at;
- approver identity;
- one_time_use ou contador explicitamente definido.

Alterar tool, target ou parâmetros invalida a aprovação.

## 5. Human-in-the-loop

A interface pode ser CLI ou web, mas precisa mostrar antes da decisão:

- quem pediu;
- o que será executado;
- sobre qual recurso;
- classificação;
- motivo da política;
- digest dos parâmetros;
- validade da aprovação.

Aprovar “ação genérica” sem binding de parâmetros não satisfaz a POC.

## 6. Evidência de decisão

Cada decisão deve gerar eventos separados:

```text
agent.tool_requested
policy.evaluated
approval.requested
approval.granted
tool.executed
```

ou:

```text
agent.tool_requested
policy.evaluated
tool.denied
```

## 7. Testes P0

- LOW permitido => PASS;
- HIGH sem aprovação => DENY;
- HIGH com aprovação válida => PASS;
- BLOCKED mesmo com pedido do agente => DENY;
- parâmetros alterados após aprovação => DENY;
- policy_version divergente => DENY ou reavaliação explícita.

## 8. Princípio de topologia

A POC deve declarar claramente:

> O gateway só governa ações que realmente passam por ele.

Se o agente receber credenciais e rota direta para o upstream, nenhum software no gateway pode magicamente impedir o bypass. O cenário P0 deve, portanto, colocar o upstream atrás do gateway controlado.
