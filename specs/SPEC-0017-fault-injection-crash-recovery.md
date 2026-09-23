# SPEC-0017 — Fault Injection, Crash Recovery e Estados UNKNOWN

**Status:** Proposed  
**Classe:** Resilience / Durability  
**Prioridade:** P1  
**Dependências:** SPEC-0002, SPEC-0004, SPEC-0005

## 1. Princípio

Uma falha no pior instante não pode transformar incerteza em sucesso.

## 2. Cenários

| ID | Falha | Esperado |
|---|---|---|
| FLT-01 | kill durante append | recovery sem corrupção silenciosa |
| FLT-02 | disk full antes de evidência crítica | HIGH não retorna PASS |
| FLT-03 | gateway cai após approval antes de execute | estado recuperável |
| FLT-04 | upstream timeout antes de efeito | FAILED/UNKNOWN |
| FLT-05 | upstream timeout após efeito | UNKNOWN/reconcile |
| FLT-06 | exporter cai no meio | pacote parcial não valida |
| FLT-07 | verifier cai | pacote permanece imutável |
| FLT-08 | policy store indisponível | HIGH DENY |
| FLT-09 | clock salta | expiry segue clock policy e evento é registrado |
| FLT-10 | restart com approval pendente | estado e TTL consistentes |

## 3. UNKNOWN

UNKNOWN é resultado válido quando não existe evidência suficiente para distinguir execução de não execução.

É proibido converter UNKNOWN em SUCCEEDED apenas para simplificar a UI.

## 4. Reconciliation

P1 deve reconciliar efeitos ambíguos contra o upstream sintético e registrar o resultado como novo evento, preservando o UNKNOWN original.

## 5. Chaos controlado

Fault injection é determinístico e local. Falhas aleatórias ficam fora da apresentação principal.
