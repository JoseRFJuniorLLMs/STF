# SPEC-0006 — Testes Adversariais e Casos de Abuso

**Status:** Proposed  
**Classe:** Security Testing / Abuse Cases  
**Prioridade:** P0  
**Dependências:** SPEC-0005

## 1. Objetivo

Transformar a apresentação em teste de segurança, não em happy path teatral.

## 2. Matriz P0

| ID | Ataque | Resultado |
|---|---|---|
| ADV-01 | replay de approval_id já consumido | DENY |
| ADV-02 | aprovação expirada | DENY |
| ADV-03 | aprovação do Agent-A usada pelo Agent-B | DENY |
| ADV-04 | parâmetros alterados após aprovação | DENY |
| ADV-05 | resource_id trocado | DENY |
| ADV-06 | chamada HIGH sem gateway | não alcança upstream no topology P0 |
| ADV-07 | flood de requests de aprovação | rate limit / bounded |
| ADV-08 | request malformado | REJECT |
| ADV-09 | payload acima do limite | REJECT |
| ADV-10 | policy desconhecida | DENY fail-closed |
| ADV-11 | falha de persistência crítica | sem PASS falso |
| ADV-12 | adulteração de Evidence Bundle | DETECTED |

## 3. Replay

Uma aprovação de uso único deve ser atomicamente consumida ou marcada de forma que duas execuções concorrentes não resultem em dois efeitos válidos.

Teste concorrente mínimo:

- duas requisições usam o mesmo approval_id;
- no máximo uma pode chegar ao upstream;
- a outra retorna DENY/REPLAY_DETECTED.

## 4. Expiração

Não basta comparar data no cliente. A validação ocorre no ponto de enforcement.

O relógio utilizado e sua natureza devem ser registrados. Na POC, tempo local não deve ser chamado de trusted time.

## 5. Binding de identidade

A aprovação deve estar associada à identidade canônica do agente/requester.

Trocar apenas um campo textual não pode enganar a comparação; a POC deve normalizar a identidade antes do binding.

## 6. Fail-closed

Casos em que a ação HIGH deve falhar fechada:

- policy store indisponível;
- aprovação não encontrada;
- digest divergente;
- identity binding incompleto;
- estado da aprovação desconhecido;
- storage crítico indisponível quando evidência prévia for obrigatória.

## 7. Resource limits

Definir no mínimo:

- max request bytes;
- max concurrent approvals;
- max pending approvals por principal;
- timeout de decisão;
- max response bytes;
- rate limit de ferramenta HIGH.

## 8. Evidência dos testes

Cada teste adversarial produz:

```json
{
  "test_id": "ADV-01",
  "expected": "DENY",
  "observed": "DENY",
  "reason": "REPLAY_DETECTED",
  "correlation_id": "...",
  "evidence_refs": ["..."],
  "result": "PASS"
}
```

## 9. Critério

A POC não passa porque ataques foram bloqueados manualmente. O bloqueio deve ser produto da política/código e reproduzível pelo script.


---

## 10. Campanha ampliada

| ID | Caso | Resultado |
|---|---|---|
| ADV-13 | 64 DENY concorrentes | 0 hits no upstream |
| ADV-14 | approval double-spend | <=1 hit |
| ADV-15 | identity header oversized | REJECT |
| ADV-16 | path traversal no bundle | FAIL |
| ADV-17 | symlink no bundle | FAIL |
| ADV-18 | dois paths normalizados iguais | FAIL |
| ADV-19 | campo crítico desconhecido | REJECT ou policy explícita |
| ADV-20 | policy reload inválido | última válida ou fail-closed |
| ADV-21 | policy muda entre approve/execute | DENY |
| ADV-22 | correlation collision | sem confusão de autorização |
| ADV-23 | mesmo event_id com bytes diferentes | CONFLICT |
| ADV-24 | timeout após possível efeito | UNKNOWN/reconcile |
| ADV-25 | exporter interrompido | pacote parcial FAIL |
| ADV-26 | objeto gigante | bounded/reject |
| ADV-27 | zip bomb, se ZIP existir | bounded/reject |
| ADV-28 | arquivo extra | policy explícita |
| ADV-29 | segredo sintético em log | redaction/alert |
| ADV-30 | egress não declarado | gate FAIL |

## 11. Oráculo independente

Todo teste de bloqueio registra duas fontes:

1. decisão do gateway;
2. contador real do upstream sintético.

`DENY` com `upstream_delta > 0` é FAIL.

## 12. Repetibilidade

Cada ataque produz attack_id, seed, expected, observed, upstream_delta, duration e evidence_refs.

## 13. Mutation testing

Provas de sabotagem mínimas:

- replay;
- identity binding;
- parameters digest;
- object/Merkle digest;
- traversal;
- UNKNOWN->SUCCEEDED.

Cada mutação deve derrubar um teste específico.

## 14. Segurança do red team

A ferramenta de ataque é confinada à rede/loopback da POC e usa allowlist de destinos. Não recebe credencial real nem capacidade de atingir infraestrutura externa.
