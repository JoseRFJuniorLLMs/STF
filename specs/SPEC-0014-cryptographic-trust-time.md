# SPEC-0014 — Criptografia, Domínios de Confiança e Tempo

**Status:** Proposed  
**Classe:** Cryptography / Trusted Time  
**Prioridade:** P0/P1  
**Dependências:** SPEC-0004, SPEC-0007

## 1. Princípio

Hash, assinatura, carimbo de tempo e confiança institucional respondem perguntas diferentes.

A POC deve impedir que “tem hash” seja apresentado como “tem autenticidade institucional”.

## 2. Digests

- SHA-256 para interoperabilidade do Evidence Bundle;
- BLAKE3 quando fornecido pelo mecanismo Heraclitus/Merkle;
- algoritmo, domínio e encoding versionados.

## 3. Domain separation

Usos distintos devem possuir domínio distinto ou estrutura canônica não ambígua:

```text
STF-POC:EVENT:v1
STF-POC:MANIFEST:v1
STF-POC:APPROVAL:v1
```

## 4. Estados de tempo

- CLAIMED_LOCAL_TIME;
- HLC;
- RFC3161_PRESENT_UNVERIFIED;
- RFC3161_CRYPTO_VERIFIED;
- EXTERNAL_TRUST_VERIFIED.

Cada avanço exige evidência correspondente.

## 5. Trust store

Trust anchors nunca são chamados de institucionais sem origem documentada.

Na POC o trust store pode ser LAB/POC. Confiança institucional permanece UNVERIFIED.

## 6. Assinatura de laboratório

Se manifests forem assinados:

- chave de laboratório;
- fingerprint publicado;
- privada fora do repositório;
- estado LAB_SIGNATURE_VALID;
- nunca INSTITUTIONAL_SIGNATURE_VALID.

## 7. RFC 3161

Quando usado, validar status da resposta, imprint, nonce, policy, assinatura e cadeia conforme capacidades disponíveis. Revogação e limitações devem ser explicitadas.

## 8. Key management

P1 avalia integração KeyProvider/HSM. Ausência de HSM não bloqueia P0 local.

Em perfil institucional futuro, fallback silencioso de HSM obrigatório para chave de arquivo é proibido.
