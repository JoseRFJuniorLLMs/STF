# SPEC-0028 — Document & LLM Injection Forensics

**Status:** Implemented in POC / institutional qualification pending  
**Classe:** Document Security / AI Safety / Forensics  
**Prioridade:** P0  
**Dependências:** SPEC-0004, SPEC-0005, SPEC-0007, SPEC-0013, SPEC-0019, SPEC-0025, SPEC-0026  
**HeraclitusDB:** SPEC-0092 — Document & LLM Injection Firewall

## 1. Objetivo

Definir o contrato técnico da POC para detectar, explicar, conter e provar tentativas de **indirect prompt injection** veiculadas por documentos processuais sintéticos.

A SPEC cobre duas propriedades distintas:

1. **Detecção forense:** tornar observável a diferença entre o que um humano vê e o que uma máquina extrai.
2. **Limitação de autoridade:** impedir que conteúdo documental, detectado ou não, adquira autoridade operacional sobre agentes, ferramentas ou sistemas protegidos.

A segunda propriedade é obrigatória mesmo quando a primeira falha.

## 2. Invariante de segurança

```text
DOCUMENTO
   |
   v
UNTRUSTED_DOCUMENT
   |
   v
DATA_ONLY
   |
   +--> pode ser lido, classificado, resumido
   |
   X--> não pode virar SYSTEM / POLICY / TOOL AUTHORITY
```

Nenhum texto vindo de documento pode, por si só:

- habilitar ferramentas;
- mudar política;
- aprovar ação privilegiada;
- elevar identidade;
- alterar parâmetros já aprovados;
- escrever em sistema protegido;
- exportar conteúdo restrito.

A autoridade para efeitos privilegiados pertence ao Policy Gateway, não ao documento.

## 3. Escopo

A POC deve representar, de forma sintética e controlada:

- PDF/text layer;
- cabeçalho e rodapé;
- metadados;
- anotações;
- campos de formulário;
- anexos;
- conteúdo invisível ao humano;
- conteúdo visível à máquina;
- Unicode invisível/bidirecional;
- fragmentação;
- instruções dirigidas a LLM;
- coerção de tool/action;
- sanitização;
- quarentena;
- decisão de policy;
- prova de efeito ou ausência de efeito;
- cadeia de custódia.

Não faz parte do escopo afirmar cobertura universal de todo formato PDF possível.

## 4. Modelo estrutural mínimo

Cada span documental deve poder carregar:

```text
text
page
bbox
font_size
foreground
background
opacity
source_region
human_visible
zero_width
fragmented
clipped
outside_page
behind_image
transform_scale
rotation
```

`source_region` deve distinguir, no mínimo:

- body;
- header;
- footer;
- metadata;
- annotation;
- form;
- attachment.

## 5. Representações obrigatórias

Para cada documento analisado, a POC deve produzir e preservar:

1. **Original Bytes** — bytes recebidos.
2. **Human View** — conteúdo efetivamente visível.
3. **Machine View** — conteúdo extraído estruturalmente.
4. **Normalized View** — conteúdo após normalização de caracteres invisíveis.
5. **Hidden/Machine-only View** — diferença estrutural relevante.
6. **Sanitized View** — conteúdo autorizado para leitor IA.

Cada camada deve possuir hash independente quando aplicável.

## 6. Requisitos normativos

### PI-REQ-001 — Original imutável

A sanitização MUST criar nova representação e MUST NOT alterar os bytes originais.

### PI-REQ-002 — Human × Machine differential

A POC MUST calcular e expor diferença entre visão humana e visão da máquina.

Deve informar, no mínimo:

- tamanho de cada representação;
- conteúdo exclusivo da máquina;
- quantidade de tokens exclusivos da máquina.

### PI-REQ-003 — Visual steganography

A POC MUST detectar, de forma explicável:

- white-on-white/same-color;
- micro-font;
- baixa opacidade.

Regras atuais:

```text
DOC-STEG-001
DOC-STEG-004
```

### PI-REQ-004 — Geometric concealment

A POC MUST detectar:

- clipping;
- off-page;
- behind-image;
- transform scale próximo de zero.

Regra:

```text
DOC-GEOM-001
```

### PI-REQ-005 — Unicode/fragmentation

A POC MUST detectar:

- zero-width characters;
- bidi controls;
- fragmentação artificial.

Regras:

```text
DOC-STEG-002
DOC-FRAG-003
```

### PI-REQ-006 — Header/footer/metadata injection

Instruções dirigidas a IA em regiões estruturais sensíveis MUST ser classificadas separadamente.

```text
DOC-HDR-001
DOC-META-001
```

### PI-REQ-007 — Model instruction coercion

A POC MUST detectar linguagem que tenta assumir autoridade sobre o modelo, sem tratar a mera menção acadêmica ao tema "prompt injection" como ataque.

Regras:

```text
DOC-AI-001
DOC-AI-002
```

O controle negativo legítimo é requisito de qualificação.

### PI-REQ-008 — Tool abuse

Conteúdo tentando causar ação, mutação, exportação ou exfiltração MUST produzir finding próprio.

```text
DOC-TOOL-001
```

### PI-REQ-009 — Explainability

Cada finding MUST conter:

- finding_id;
- rule_id;
- categoria;
- severidade;
- evidência;
- localização;
- explicação;
- confiança.

É proibido usar apenas um score opaco como justificativa de bloqueio.

### PI-REQ-010 — Quarantine

Payloads de alta criticidade MUST poder ser colocados em quarentena antes da exposição a LLM.

### PI-REQ-011 — Sanitized reader

Quando houver exposição permitida, o reader MUST receber somente representação sanitizada.

O contrato exposto deve declarar:

```text
trust=UNTRUSTED_DOCUMENT
authority=DATA_ONLY
tools_allowed=false
```

### PI-REQ-012 — Detector MISS

A POC MUST conter cenário onde o detector falha de propósito.

Nesse cenário:

- o LLM pode ser exposto;
- o conteúdo pode tentar solicitar ação protegida;
- o Policy Gateway MUST negar a ação sem credencial válida;
- `upstream_delta` MUST permanecer 0.

Este requisito prova que segurança não depende de detecção perfeita.

### PI-REQ-013 — Policy Gateway

Toda ação privilegiada MUST passar por gateway separado do reader.

O gateway deve poder verificar:

- identity binding;
- action binding;
- parameter binding;
- target binding;
- HITL;
- anti-replay;
- contexto de incidente.

### PI-REQ-014 — Effect oracle

Para qualquer DENY ou quarentena:

```text
upstream_delta == 0
executed_count == 0
```

A tela mostrar DENY não é prova suficiente.

### PI-REQ-015 — Canonical events

A POC MUST emitir eventos canônicos compatíveis conceitualmente com a SPEC-0092 do HeraclitusDB:

```text
document.hidden_text.detected
document.obfuscation.detected
document.prompt_injection.detected
document.tool_coercion.detected
document.quarantined
document.sanitized.created
agent.policy.evaluated
```

Eventos documentais devem carregar, quando disponível:

- schema_version;
- document_id;
- document_sha256;
- finding_id;
- rule_id;
- page;
- severity;
- trust;
- authority.

### PI-REQ-016 — Forensic heatmap

O dashboard MUST permitir localizar achados por página e `bbox`.

Cada hotspot deve mostrar regra(s) relacionada(s) e conteúdo extraído.

### PI-REQ-017 — Human × Machine UI

O dashboard MUST permitir comparação direta entre visão humana e visão da máquina.

### PI-REQ-018 — Causal graph

A visualização MUST representar a fronteira de autoridade.

Fluxo de referência:

```text
Document
 -> Parser
 -> Finding
 -> Quarantine/Sanitization
 -> Reader LLM
 -> Authority Boundary
 -> Policy Gateway
 -> Effect / No Effect
 -> Evidence
```

### PI-REQ-019 — Evidence Bundle

O pacote de evidência MUST incluir ou referenciar:

- hash do original;
- hashes das representações derivadas;
- findings;
- differential;
- security contract;
- policy decision;
- upstream_delta;
- cadeia de custódia.

### PI-REQ-020 — Offline verification

O verificador offline deve continuar distinguindo:

```text
PASS
FAIL
UNVERIFIED
```

Integrações institucionais ausentes não podem ser apresentadas como PASS.

## 7. Cenários obrigatórios

### Caso 01 — Esteganografia visual

Cenário sintético inspirado no incidente público associado ao gabinete do Min. Cristiano Zanin.

Deve demonstrar:

- conteúdo oculto;
- findings explicáveis;
- quarentena pré-LLM;
- `upstream_delta=0`.

### Caso 02 — Instruction override em cabeçalho

Cenário sintético inspirado no caso público noticiado em 01/10/2026 sob relatoria do Min. Alexandre de Moraes.

Deve demonstrar:

- instrução em região de header;
- micro-font/mesma cor/baixa opacidade;
- `DOC-HDR-001`;
- `DOC-STEG-004`;
- quarentena;
- `DATA_ONLY`;
- `upstream_delta=0`.

A POC não reproduz o documento real.

### Caso 03 — Tool abuse / exfiltração

Cenário VitórIA sintético.

Deve demonstrar:

- tool coercion;
- `DOC-TOOL-001`;
- Policy Gateway;
- zero efeito no alvo.

### Caso 04 — Zero-day / detector MISS

O detector deve ser forçado a permitir o conteúdo.

A barreira 2 deve continuar bloqueando a ação privilegiada.

### Caso 05 — Negative control

Documento acadêmico/legítimo pode discutir segurança de IA sem ser automaticamente classificado como ataque.

Esse cenário MUST permanecer ALLOWED.

## 8. Matriz de ameaça

| Vetor | Finding/Rule | Resposta |
|---|---|---|
| white-on-white | DOC-STEG-001 | finding/quarantine conforme contexto |
| micro-font | DOC-STEG-001 | finding/quarantine |
| baixa opacidade | DOC-STEG-004 | finding |
| clipped/off-page | DOC-GEOM-001 | finding |
| behind-image | DOC-GEOM-001 | finding |
| tiny transform | DOC-GEOM-001 | finding |
| zero-width/bidi | DOC-STEG-002 | finding |
| fragmentação | DOC-FRAG-003 | finding |
| header/footer | DOC-HDR-001 | critical finding |
| metadata | DOC-META-001 | critical finding |
| instruction override | DOC-AI-001/002 | critical finding |
| tool coercion | DOC-TOOL-001 | deny/quarantine |
| detector miss | policy layer | deny / upstream=0 |
| texto acadêmico benigno | negative control | allowed |

## 9. Visualização

A Central Forense de Segurança de IA deve expor, no mínimo:

- seletor dos cinco cenários;
- Human View;
- Structural/Machine View;
- Forensic View;
- Sanitized View;
- painel Human × Machine;
- machine-only token count;
- heatmap por página;
- lista de findings;
- explicação "por que foi bloqueado";
- security contract;
- policy decision;
- upstream_delta;
- cadeia de custódia;
- Evidence Bundle;
- Offline Verifier.

## 10. Segurança de interface

A interface nunca pode sugerir que:

- o STF utiliza esta POC;
- o HeraclitusDB estava presente no incidente real;
- o dashboard constitui perícia oficial;
- hash local equivale a assinatura institucional;
- timestamp sintético equivale a TSA institucional;
- um detector é infalível.

## 11. Testes de aceitação

Os seguintes gates devem passar:

```text
PI-T01 hidden stego -> QUARANTINED
PI-T02 original bytes -> unchanged
PI-T03 header override -> DOC-HDR-001
PI-T04 low opacity -> DOC-STEG-004
PI-T05 detector MISS -> DENY
PI-T06 detector MISS -> upstream_delta=0
PI-T07 tool abuse -> DOC-TOOL-001
PI-T08 benign academic -> ALLOWED
PI-T09 reader authority -> DATA_ONLY
PI-T10 reader tools -> false
PI-T11 evidence bundle -> PASS
PI-T12 external timestamp absent -> UNVERIFIED
PI-T13 institutional signature absent -> UNVERIFIED
PI-T14 JS forensic UI -> syntax gate PASS
PI-T15 HTTP smoke -> PASS
```

## 12. Implementação atual

| Requisito | Implementação |
|---|---|
| PI-REQ-001..015 | `poc/zanin_defense.py` |
| PI-REQ-016..018 | `poc/dashboard/zanin.js`, `zanin.css` |
| PI-REQ-019..020 | EvidenceBundleManager / Offline Verifier |
| cenários | `SCENARIOS` em `poc/zanin_defense.py` |
| testes | `poc/tests/test_zanin.py` |
| CI | `.github/workflows/poc-ci.yml` |
| documentação operacional | `docs/ZANIN-PROMPT-INJECTION-LAB.md` |
| core genérico | HeraclitusDB SPEC-0092 |

## 13. Relação com HeraclitusDB SPEC-0092

A divisão de responsabilidade é intencional:

```text
HeraclitusDB
  SPEC-0092
  -> primitives reutilizáveis
  -> DocumentFirewall
  -> canonical events
  -> DATA_ONLY authority
  -> ReaderPayload
  -> Sentinel integration

STF POC
  SPEC-0028
  -> cenários sintéticos
  -> dashboard forense
  -> heatmap
  -> demonstração Human × Machine
  -> Evidence Bundle da POC
  -> qualification
```

A POC não deve duplicar o core definitivo quando integração real estiver disponível.

## 14. Limitações conhecidas

A implementação atual da POC:

- usa representação sintética de estrutura documental;
- não é parser PDF universal;
- não executa OCR real;
- não inspeciona todos os tipos possíveis de objeto PDF;
- não possui integração institucional;
- não possui assinatura ICP-Brasil institucional;
- não possui TSA institucional;
- não prova cobertura de todo bypass possível.

Essas limitações não invalidam o objetivo da POC: demonstrar a arquitetura de defesa em profundidade, os invariantes de autoridade e a evidência de ausência de efeito.

## 15. Critério de conclusão

A SPEC é considerada implementada na POC quando:

1. os cinco cenários são executáveis;
2. o controle benigno não gera falso positivo;
3. o caso detector-MISS mantém `upstream_delta=0`;
4. o dashboard expõe Human × Machine e heatmap;
5. os eventos canônicos são emitidos;
6. o Evidence Bundle carrega contrato e differential;
7. os testes automatizados passam;
8. o CI valida Python, smoke HTTP e JavaScript.

Qualificação institucional permanece fora do escopo até existir piloto autorizado.
