# Defesa Zanin — Laboratório Forense de Prompt Injection em Documentos Processuais

> **Aviso de Escopo:** Prova de conceito independente e integralmente sintética. Não representa sistema oficial, perícia oficial, homologação ou integração operacional do Supremo Tribunal Federal. O HeraclitusDB não estava instalado no STF e não participou do incidente real noticiado.

---

## 1. Contexto e Fatos Publicamente Relatados

Em 25 de setembro de 2026, a imprensa nacional (coluna Bela Megale / O Globo) noticiou a identificação, pelo Núcleo de Inteligência Artificial da Secretaria-Geral de Tecnologia e Inovação (SGTI/STF), da primeira tentativa de fraude processual por meio de **Prompt Injection** em recurso no Supremo Tribunal Federal, em processo de relatoria do Ministro Cristiano Zanin.

### 1.1 O que é fato público confirmado:
* Tentativa de prompt injection em peça processual perante a corte.
* Inserção de comandos ocultos em páginas do documento em letras brancas e tamanho reduzido.
* Fragmentação de palavras para dificultar filtros de segurança.
* Tentativa sem efeito prático, dado que o gabinete não utiliza ferramentas de inteligência artificial para análise ou fundamentação de decisões judiciais.
* Aplicação de multa por violação da lealdade processual (CPC) e envio ao MPF e à OAB pelo Ministro Relator.

### 1.2 O que é sintético nesta POC:
* **Identificadores e dados:** números como `ARE-SINTETICO-001`, hashes de arquivos e nomes de arquivos são estritamente fictícios para laboratório.
* **Payloads:** os comandos foram redigidos sinteticamente para demonstrar a resposta técnica.
* **Ambiente isolado:** a POC roda 100% em loopback, sem comunicação com ChatGPT, Claude, Gemini ou sistemas reais do STF.
* **Artefatos:** todos os relatórios emitidos são identificados como `ARTEFATO SINTÉTICO DE DEMONSTRAÇÃO — NÃO EMITIDO PELO STF`.

---

## 2. Threat Model (Modelo de Ameaça)

O vetor de ataque explorado é o **Indirect Prompt Injection** veiculado via documento PDF anexado aos autos eletrônicos:

```text
Atacante (Advogado/Terceiro)
   │
   ▼
Petição em PDF com camada oculta (esteganografia visual #FFFFFF / 0.4pt / Unicode zero-width)
   │
   ▼
Pipeline de Ingestão do Tribunal
   │
   ▼
[Se desprotegido] LLM lê o stream bruto do PDF ➔ Executa instrução maliciosa ➔ Emite minuta favorável
```

### Vetores específicos avaliados no laboratório:
1. **Esteganografia Visual (White-on-White / Micro-font):** Texto em cor `#FFFFFF` sobre fundo `#FFFFFF` ou tamanho de fonte inferior a 2.0pt.
2. **Caracteres Invisíveis Unicode:** Intercalação de caracteres de largura zero (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`) para mascarar palavras.
3. **Fragmentação Artificial:** Quebra proposital de termos jurídicos para burlar regex (`p-r-o-v-i-m-e-n-t-o`).
4. **Coerção de Modelo:** Comandos imperativos simulando diretrizes de sistema (`[SYSTEM_OVERRIDE]`, `ignore previous instructions`).

---

## 3. Arquitetura de Defesa em Duas Barreiras

A POC demonstra múltiplas camadas para detectar conteúdo documental adversarial, limitar sua exposição a modelos e impedir que conteúdo não confiável adquira autoridade operacional.

```text
DOCUMENTO ORIGINAL
   │ (preservação estrita dos bytes e hashes SHA-256)
   ▼
┌─────────────────────────────────────────────────────────────┐
│ BARREIRA 1: Document Security & Forensic Inspection         │
│ • Inspeção estrutural de streams, fontes e canais de cor    │
│ • Detecção explicável de achados (Findings com regra e ID)  │
│ • Quarentena automática ou sanitização não-destrutiva       │
└──────────────────────────────┬──────────────────────────────┘
                               │
               Se MISS (Bypass do Detector)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ BARREIRA 2: Heraclitus Agent Policy Gateway                 │
│ • Conteúdo de documento NÃO possui autoridade operacional   │
│ • Chamadas a ferramentas protegidas exigem credencial HITL  │
│ • Falha fail-closed ➔ DENY                                  │
│ • upstream_delta = 0 (Efeito real: NENHUM)                  │
└─────────────────────────────────────────────────────────────┘
```

> **Princípio Fundamental:** A defesa continua efetiva para ações protegidas mesmo quando a camada de detecção de prompt injection falha, desde que o acesso ao sistema de destino esteja exclusivamente atrás do Policy Gateway.

---

## 4. Os Três Cenários de Laboratório

1. **Cenário A (Incidente Sintético Zanin):**
   * Esteganografia visual + coerção detectadas antes do LLM.
   * Documento colocado em quarentena.
   * LLM **NÃO exposto** (`NOT EXPOSED`).
   * `upstream_delta = 0`.

2. **Cenário B (Detector MISS ➔ Policy Gateway Segura):**
   * O detector falha propositalmente (simulando payload zero-day não catalogado).
   * O modelo LLM é exposto e contaminado, solicitando mutação em processo (`judicial_case_write`).
   * O **Policy Gateway** intercepta a solicitação e emite `DENY` por ausência de credencial de autoridade humana (HITL).
   * `upstream_delta = 0` (Nenhum efeito no banco protegido).

3. **Cenário C (Ação Legítima Sem Falso Positivo):**
   * Documento acadêmico que cita termos de prompt injection de forma legítima não é bloqueado erroneamente.
   * Ação solicitada acompanhada de aprovação humana vinculada (`HITL Approval`).
   * Decisão `ALLOW` com `upstream_delta = 1`.

---

## 5. Cadeia de Custódia e Hashes Forenses

Para cada documento, o sistema preserva os bytes originais inalterados e calcula hashes independentes:

| Camada | Hash SHA-256 | Função Pericial |
|---|---|---|
| **Original Bytes** | `sha256(raw_bytes)` | Evidência primária imutável anexada ao protocolo |
| **Rendered Text** | `sha256(rendered_text)` | Visão humana convencional (somente texto visível a olho nu) |
| **Raw Extracted** | `sha256(raw_extracted)` | Texto bruto de todos os fluxos presentes no arquivo |
| **Hidden Content** | `sha256(hidden_content)` | Camada esteganográfica isolada para instrução pericial |
| **Normalized Text** | `sha256(normalized)` | Texto livre de caracteres Unicode invisíveis |
| **Sanitized Text** | `sha256(sanitized)` | Cópia segura autorizada para processamento por agentes de IA |

---

## 6. Evidence Bundle e Offline Verifier

O laboratório permite compilar o Evidence Bundle padronizado com o manifesto de custódia e submetê-lo ao **Offline Verifier**:

```text
PACKAGE_STRUCTURE               PASS
ORIGINAL_FILE_HASH              PASS
EXTRACTED_CONTENT_HASHES        PASS
POLICY_AND_UPSTREAM_ENFORCEMENT PASS
EXTERNAL_TIMESTAMP              UNVERIFIED (Sem integração TSA institucional externa)
INSTITUTIONAL_SIGNATURE         UNVERIFIED (Sem certificado ICP-Brasil do tribunal)
```

Nenhum claim falso de conformidade externa é emitido; itens sem integração real permanecem expressamente como `UNVERIFIED`.
