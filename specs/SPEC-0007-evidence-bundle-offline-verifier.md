# SPEC-0007 — Evidence Bundle e Verificador Independente Offline

**Status:** Proposed / POC Adapter Required  
**Classe:** Digital Evidence / Export / Verification  
**Prioridade:** P0  
**Dependências:** SPEC-0004, SPEC-0005

## 1. Contexto

O HeraclitusDB possui uma SPEC principal para pacote forense e cadeia de custódia, mas essa capacidade completa permanece classificada como Draft/Proposed no baseline consultado.

Logo, esta POC não pode declarar que o produto completo já existe. Ela implementará somente o subconjunto mínimo necessário para demonstrar exportação e verificação independente.

## 2. Estrutura mínima

```text
evidence-package/
├── manifest.json
├── manifest.sha256
├── events/
│   └── events.jsonl
├── proofs/
│   ├── merkle.json
│   └── hrkl-range.json
├── audit/
│   ├── policy-decisions.jsonl
│   └── approvals.jsonl
├── build/
│   └── build-identity.json
└── report/
    └── verification-summary.json
```

Arquivos opcionais:

```text
proofs/timestamp.tsr
proofs/signature.p7s
certificates/
sbom/
```

## 3. Manifesto

Campos mínimos:

- schema_version;
- package_id;
- case_id sintético;
- source_build;
- created_at_claimed;
- event_count;
- lsn_range;
- object list;
- SHA-256 de cada objeto;
- BLAKE3 quando disponível;
- Merkle root;
- policy version;
- exporter identity sintética;
- limitations.

## 4. Regra de autoridade

O manifesto estruturado é a autoridade do pacote.

HTML/PDF, se gerados, são apenas apresentação humana.

## 5. Verificador

Comando alvo:

```text
stf-poc verify ./evidence-package
```

ou adaptador equivalente sobre CLI do HeraclitusDB.

A verificação deve funcionar com:

- rede desabilitada;
- banco de origem indisponível;
- exporter parado.

## 6. Saída mínima

```text
PACKAGE_STRUCTURE        PASS
MANIFEST_DIGEST          PASS
OBJECT_DIGESTS           PASS
EVENT_COUNT              PASS
MERKLE_PROOF             PASS
AUDIT_REFERENCES         PASS
TIMESTAMP                NOT_CONFIGURED
SIGNATURE                NOT_CONFIGURED
EXTERNAL_TRUST           UNVERIFIED
OVERALL_LOCAL_INTEGRITY  PASS
```

## 7. Confiança externa

Ausência de:

- ACT real;
- cadeia ICP-Brasil instalada;
- assinatura institucional;
- HSM institucional;

nunca pode produzir PASS nesses eixos.

## 8. Sabotagem

Após gerar pacote válido:

1. alterar decisão `DENY` para `ALLOW` em um objeto;
2. executar verificador novamente;
3. exigir OBJECT_DIGESTS=FAIL ou MERKLE_PROOF=FAIL;
4. overall deve deixar de ser PASS.

Teste adicional: apagar um arquivo listado no manifesto.

Resultado: FAIL.

## 9. Separação de processos

Preferência forte:

- exporter e verifier não compartilham processo;
- verifier lê apenas arquivos do pacote;
- verifier não chama API Heraclitus remota.

## 10. Futuro

Uma eventual evolução pode alinhar completamente o formato ao SPEC-0087 do HeraclitusDB, incluindo custody chain, assinatura, TSA, SBOM e relatório técnico formal.
