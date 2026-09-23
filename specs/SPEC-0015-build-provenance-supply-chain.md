# SPEC-0015 — Build Provenance, SBOM e Supply Chain

**Status:** Proposed  
**Classe:** Software Supply Chain  
**Prioridade:** P1  
**Dependências:** SPEC-0009

## 1. Objetivo

Responder: quais fontes e dependências produziram exatamente o artefato demonstrado?

## 2. Build manifest

```json
{
  "source_repo":"JoseRFJuniorLLMs/STF",
  "source_commit":"...",
  "heraclitus_commit":"...",
  "toolchain":"...",
  "target":"...",
  "lockfile_sha256":"...",
  "artifact_sha256":"...",
  "builder_profile":"poc"
}
```

## 3. SBOM

Preferir CycloneDX ou SPDX e cobrir binários POC, Heraclitus utilizado, imagens e dependências relevantes.

## 4. Gates de dependência

- lockfile versionado;
- dependency drift bloqueado;
- inventário de licenças;
- vulnerability scan documentado;
- dependência Git fixada em commit;
- imagens fixadas por digest.

Erro do scanner é ERROR/NOT_ASSESSED, nunca “sem vulnerabilidades”.

## 5. CI provenance

Artefato qualificado aponta para commit, workflow/run quando aplicável, hashes e logs dos gates.

## 6. Assinatura de artefato

P1 pode usar cosign/minisign ou equivalente em laboratório. A assinatura prova posse da chave usada, não autoridade institucional inexistente.

## 7. Rebuild

Meta de maturidade: rebuild limpo e comparação de bytes ou, quando não determinístico, comparação de propriedades com fontes de variabilidade documentadas.
