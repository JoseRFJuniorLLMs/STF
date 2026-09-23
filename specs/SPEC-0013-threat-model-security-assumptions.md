# SPEC-0013 — Threat Model, Ativos e Hipóteses de Segurança

**Status:** Proposed  
**Classe:** Security Architecture / Threat Modeling  
**Prioridade:** P0  
**Dependências:** SPEC-0002, SPEC-0005, SPEC-0007

## 1. Objetivo

Definir quem pode atacar a POC, quais ativos importam e quais propriedades estão sendo defendidas.

## 2. Ativos

- histórico canônico;
- identidade de principal/agente;
- policies e approvals;
- credencial do upstream;
- Evidence Bundle;
- build artifacts;
- trust store;
- configuração;
- resultados de teste.

## 3. Adversários

### A1 — agente comprometido
Produz requests arbitrários e tenta tool abuse, mas não possui credencial direta do upstream.

### A2 — cliente malicioso
Envia payloads inválidos, grandes, duplicados ou inconsistentes.

### A3 — operador com privilégio parcial
Pode aprovar ações do seu papel, mas não deve conseguir alterar retrospectivamente evidência sem detecção dentro do modelo testado.

### A4 — atacante com acesso ao bundle
Pode modificar, apagar, inserir ou reordenar arquivos.

### A5 — falha não maliciosa
Crash, disk full, timeout e corrupção parcial são ameaças à integridade.

## 4. Fora do modelo P0

Não alegar defesa absoluta contra atacante que controla simultaneamente kernel, binário, storage, chaves, verifier e cadeia de distribuição.

Mitigações reais exigem fronteiras independentes como HSM, WORM, attestation, assinatura externa e trust anchors.

## 5. Trust boundaries

- TB-1 input -> validation;
- TB-2 agent -> gateway;
- TB-3 gateway -> upstream;
- TB-4 runtime -> persistent history;
- TB-5 exporter -> package;
- TB-6 package -> verifier;
- TB-7 local crypto -> external trust.

Cada boundary deve possuir ao menos um teste negativo.

## 6. Objetivos de segurança

SG-01 integridade histórica; SG-02 identidade lógica; SG-03 autorização antes de efeito; SG-04 single-use approval; SG-05 tamper detection; SG-06 offline verify; SG-07 fail-closed para HIGH; SG-08 bounded resources; SG-09 build provenance; SG-10 verdade sobre limitações.

## 7. Abuse cases

Forged approval, replay, approval swap, parameter substitution, direct-upstream bypass, policy downgrade, log truncation, path traversal, verifier exhaustion e falso PASS de confiança externa.

## 8. Saída

Cada run registra a versão do threat model usada em `out/<run_id>/threat-model-profile.json`.
