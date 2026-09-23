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


---

## 9. Policy Decision Record

Toda avaliação deve persistir um registro equivalente a:

```json
{
  "decision_id":"uuid",
  "request_id":"uuid",
  "policy_version":"policy/1",
  "rule_id":"restricted-export-requires-human",
  "decision":"REQUIRE_HITL",
  "principal":"agent:research-01",
  "tool":"export_restricted_document",
  "target_digest":"...",
  "parameters_digest":"...",
  "reason_code":"HUMAN_APPROVAL_REQUIRED"
}
```

O texto humano pode variar. O `reason_code` deve ser estável e testável.

## 10. Máquina de estados

```text
PENDING --approve--> APPROVED --consume--> CONSUMED
   |                     |
   +--reject--> REJECTED  +--expiry--> EXPIRED
                         +--revoke--> REVOKED
```

Estados terminais não voltam a PENDING.

## 11. Anti-TOCTOU

Entre aprovação e execução, revalidar principal, tool, target, parameters_digest, policy_version, expiry e state da aprovação.

Divergência exige DENY ou nova avaliação.

## 12. Consumo atômico

Para approval single-use, duas execuções concorrentes usando o mesmo approval_id devem produzir `upstream_delta <= 1`.

O contador do upstream é o oráculo independente. Um 403 do gateway com efeito já realizado é FAIL.

## 13. Credenciais e bypass

O upstream sintético aceita apenas credencial/identidade do gateway. O agente não conhece nem recebe esse segredo.

## 14. Dual control P1

Para perfil crítico opcional:

- requester não aprova a própria ação;
- N aprovadores distintos;
- todos aprovam o mesmo digest;
- mudança de parâmetros invalida aprovações.

## 15. UX de aprovação

Antes de aprovar, mostrar ação, efeito, recurso, ator, origem, parâmetros, regra acionada, validade e se o approval é single-use. O operador não deve autorizar uma operação apenas olhando hashes.
