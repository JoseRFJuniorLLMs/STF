# SPEC-0016 — CI, Qualification Gates e Mutation Testing

**Status:** Proposed  
**Classe:** QA / CI / Security Qualification  
**Prioridade:** P0/P1  
**Dependências:** todas as SPECs P0

## 1. Objetivo

Fazer a POC falhar automaticamente quando um controle essencial desaparecer.

## 2. Gates Rust

Quando houver código Rust:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 3. Gates da POC

```text
poc schema-test
poc integrity-test
poc agent-redteam
poc evidence-test
poc offline-test
poc fault-test
```

## 4. Negative assertions

CI valida também:

- upstream_delta == 0 em DENY;
- external trust != PASS sem trust profile;
- verifier network calls == 0;
- segredos reais == 0;
- arquivos inesperados conforme policy.

## 5. Mutation tests

Mutações obrigatórias:

1. aceitar replay;
2. ignorar identity binding;
3. ignorar parameters_digest;
4. ignorar object digest;
5. aceitar traversal;
6. converter UNKNOWN em SUCCEEDED.

Cada mutação deve derrubar um teste específico.

## 6. Artifacts

Publicar test-results.json, qualification-summary.json, SBOM, hashes, evidence sample, verifier output e red-team report.

## 7. Segurança do CI

Sem secrets reais; permissões mínimas; PR não recebe escrita desnecessária; bundle nunca é tratado como código executável.

## 8. Gate final

`QUALIFIED_POC=true` só é derivado dos P0 verdes. Não é flag configurável manualmente.
