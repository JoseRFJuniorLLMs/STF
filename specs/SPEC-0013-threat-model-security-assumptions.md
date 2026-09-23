# SPEC-0013 — Threat Model Integrado

**Status:** Proposed  
**Prioridade:** P0

## 1. Adversário principal

`AI_ASSISTED_ATTACKER_SYNTHETIC`.

É um agente de laboratório capaz de escolher ações em um cyber range, mas sem conexão ou credencial para qualquer ativo do STF.

## 2. Capacidades simuladas

- gerar tráfego suspeito;
- autenticar com identidade fictícia comprometida;
- iniciar processo fictício;
- produzir movimento lateral simulado;
- consultar banco sintético;
- acessar app sintética;
- solicitar alteração privilegiada;
- tentar replay e tamper.

A POC não precisa implementar código ofensivo real. Fixtures e ações controladas podem gerar a telemetria equivalente.

## 3. Ativos

- edge;
- identity;
- hosts;
- application;
- DB;
- process/case fictício;
- policies;
- approvals;
- evidence;
- build/trust.

## 4. Trust boundaries

TB1 edge->telemetry  
TB2 telemetry->normalizer  
TB3 raw->signal  
TB4 signals->incident  
TB5 incident->policy  
TB6 agent->gateway  
TB7 gateway->upstream  
TB8 history->export  
TB9 package->verifier

Cada boundary tem teste positivo e negativo.

## 5. Objetivos

- detectar sinais conhecidos;
- evitar correlação espúria óbvia;
- preservar provenance;
- usar incidente como contexto de decisão;
- bloquear writes não autorizados;
- detectar cover-tracks;
- verificar offline.

## 6. Limite essencial

Nenhuma ferramenta pode prometer detectar atividade que não gera/entrega telemetria.

Nenhuma ferramenta pode impedir ação que contorna todos os pontos de enforcement.

Essas duas limitações ficam visíveis na demo.
