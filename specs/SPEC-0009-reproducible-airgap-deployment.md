# SPEC-0009 — Implantação Reproduzível, Isolada e Air-Gap Friendly

**Status:** Proposed  
**Classe:** Deployment / Supply Chain / Sovereignty  
**Prioridade:** P0  
**Dependências:** SPEC-0002

## 1. Objetivo

Permitir que a POC seja executada em ambiente limpo com dependências e artefatos identificáveis, sem exigir acesso a serviços externos durante a demonstração.

## 2. Alvo operacional

Fluxo desejado:

```text
prepare artifacts
      |
      v
copy to clean host
      |
      v
verify hashes
      |
      v
docker compose up
      |
      v
run demo
      |
      v
disable network
      |
      v
verify evidence
```

Docker/Podman é recomendado para a POC, mas o contrato é de reprodutibilidade, não de fornecedor.

## 3. Artefatos

Publicar/gerar:

- build identity;
- commit SHA;
- image digests;
- SHA-256 dos binários;
- arquivo de configuração;
- fixtures;
- scripts;
- SBOM se disponível.

## 4. Dependências externas

O caminho P0 não pode depender de:

- LLM remoto;
- API comercial;
- serviço de timestamp remoto;
- GitHub durante execução;
- DNS externo;
- banco externo.

Se um LLM for usado para ilustração, deve existir fallback determinístico que produza as mesmas chamadas de tool para os testes.

## 5. Secrets

Somente secrets sintéticos ou efêmeros.

É proibido versionar:

- tokens pessoais;
- PAT GitHub;
- credenciais de órgão;
- chaves privadas institucionais;
- certificados reais sem autorização.

## 6. Rede

A POC deve documentar:

- portas;
- listeners;
- egress necessário;
- motivo de cada comunicação.

O teste final do verificador deve ocorrer com egress desabilitado.

## 7. Falha de dependência

Se componente não essencial estiver indisponível, o sistema deve degradar de maneira explícita.

Se componente essencial à decisão HIGH estiver indisponível, a ação deve falhar fechada.

## 8. Reprodutibilidade

Em ambiente limpo, um operador deve conseguir:

1. verificar artefatos;
2. subir stack;
3. rodar fixtures;
4. executar testes;
5. exportar bundle;
6. verificar bundle.

Sem editar código.

## 9. Gate

Critério P0:

```text
CLEAN_ENV_BOOT           PASS
FIXTURE_INGEST           PASS
NEGATIVE_TESTS           PASS
EVIDENCE_EXPORT          PASS
OFFLINE_VERIFY           PASS
UNDECLARED_EGRESS        0
```


---

## 10. Kit offline

A entrega deve poder ser materializada como:

```text
stf-poc-kit/
├── images/
├── bin/
├── config/
├── fixtures/
├── policies/
├── sbom/
├── hashes.txt
├── BUILD-INFO.json
└── RUNBOOK.md
```

O host da reunião não deve precisar buscar imagens ou dependências.

## 11. Hardening de runtime

Recomendado:

- imagens por digest, nunca `:latest`;
- usuário não-root;
- filesystem read-only quando compatível;
- tmpfs para temporários;
- capabilities mínimas;
- sem Docker socket;
- healthchecks;
- limites de CPU/memória;
- rede dedicada da POC.

## 12. Build identity

`BUILD-INFO.json` inclui repository, commit, `dirty=false`, toolchain, target, lockfile digest, build time declarado, SHA-256 do artefato e image digest.

## 13. Supply chain

O kit inclui lockfiles, SBOM CycloneDX/SPDX quando disponível, inventário de licenças, hashes e provenance conforme SPEC-0015.

## 14. Prova de isolamento

O verifier deve ser executado com egress realmente indisponível: namespace sem rota default, política equivalente ou mecanismo documentado.

“Não chamou internet” não é suficiente se poderia ter chamado.

## 15. Configuração de segurança

O run report registra gateway mode, policy version, approval TTL, size limits, verifier limits e trust profile.

Default que reduza segurança não pode ser ativado silenciosamente.
