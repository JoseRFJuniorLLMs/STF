# POC End-to-End — Intrusão, Abuso Pós-Compromisso e Evidência

## 1. História única

A POC usa uma única campanha:

```text
campaign_id = STF-POC-CAMPAIGN-001
incident_id = STF-POC-INCIDENT-001
```

Todos os sinais, decisões, approvals, efeitos e provas carregam referência a essa campanha.

## 2. Fase 1 — invasão

### 2.1 Sinais simulados

A campanha começa com eventos de baixa confiança:

```text
T+00 firewall     conexão permitida
T+03 waf          padrão incomum
T+08 identity     autenticação em contexto novo
T+14 host         processo incomum
T+20 network      conexão lateral sintética
T+27 db-audit     consulta fora do baseline
T+31 app          acesso a recurso restrito
```

Nenhum sinal sozinho precisa significar comprometimento.

### 2.2 Correlação

Heraclitus/Sentinel deve correlacionar por:

- principal/identidade;
- src/dst normalizados;
- host;
- session/correlation/campaign id;
- recurso;
- janela temporal;
- causalidade;
- IOC sintético;
- regra;
- baseline comportamental quando habilitado.

Saída:

```text
SecuritySignal[]
      |
      v
Temporal Security Graph
      |
      v
Incident STF-POC-INCIDENT-001
confidence: ...
severity: ...
evidence_refs: [...]
```

### 2.3 Detecção “desde a entrada”

A frase tecnicamente correta da POC é:

> O sistema correlaciona a campanha desde o **primeiro ponto de telemetria observável e ingerido**.

Não afirmar que detecta qualquer invasão no primeiro pacote de rede.

## 3. Ponte entre as fases

Quando a correlação alcança o gate configurado:

```text
INCIDENT_OPENED
COMPROMISE_SUSPECTED
campaign_id preserved
principal/resource context preserved
```

A mesma identidade comprometida passa a interagir com aplicação e banco sintéticos.

## 4. Fase 2 — objetivo do invasor

### 4.1 Ação sobre processo fictício

Recurso:

```text
case://SYNTHETIC/RE-000001
```

Tentativas:

1. read restricted metadata;
2. update case metadata;
3. alter classification;
4. export restricted document;
5. execute privileged agent tool.

### 4.2 Enforcement

Ações HIGH passam por:

```text
Identity
 -> Policy
 -> Incident Context
 -> Approval Binding
 -> HITL
 -> Execute
 -> Durable Evidence
```

Policy pode considerar o contexto da Fase 1:

```text
if principal is linked to OPEN_HIGH_RISK_INCIDENT:
    privileged action => DENY or REQUIRE_STRONGER_APPROVAL
```

Isso une SOC e governança de agentes.

## 5. Encobrimento

O atacante tenta:

- apagar evento;
- truncar arquivo;
- modificar decisão DENY para ALLOW;
- reordenar sequência;
- remover objeto do Evidence Bundle;
- reutilizar approval.

Esperado:

```text
tamper/delete/reorder => DETECTED
approval replay       => DENY
bundle corruption     => FAIL
```

## 6. Linha do tempo final

```text
FIRST_OBSERVABLE_SIGNAL
        |
        v
SECURITY SIGNALS
        |
        v
CORRELATED INCIDENT
        |
        v
COMPROMISED IDENTITY CONTEXT
        |
        v
PROCESS ACCESS
        |
        v
PRIVILEGED MODIFICATION ATTEMPT
        |
   +----+----+
   |         |
 DENY      HITL
   |         |
   +----+----+
        |
        v
TAMPER / COVER TRACKS
        |
        v
DETECTED
        |
        v
EVIDENCE PACKAGE
        |
        v
OFFLINE VERIFY
```

## 7. O que a POC prova

- multi-source normalization;
- rules/signals;
- temporal correlation;
- incident graph;
- provenance;
- incident-aware policy;
- privileged action control;
- post-event integrity;
- independent verification.

## 8. O que não prova

- cobertura de todos os vetores de ataque;
- integração real com rede ou sistemas do STF;
- eficácia de um produto de EDR/WAF específico;
- prevenção absoluta;
- admissibilidade jurídica automática;
- confiança institucional sem trust anchors do órgão.
