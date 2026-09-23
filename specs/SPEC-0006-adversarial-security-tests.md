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
