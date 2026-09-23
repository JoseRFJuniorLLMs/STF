# Baseline técnico do HeraclitusDB para a POC STF

**Data da revisão:** 23/09/2026  
**Baseline observado:** commit `8bcdd0a5c881a6be7c965fc36970095cc46f6f6a` nas buscas e arquivos consultados.

Este documento impede que a POC confunda código existente com roadmap.

## Capacidades observadas no código

### HRKL / integridade

Foram observados no repositório principal:

- LSN e HLC;
- CRC por registro;
- Merkle/BLAKE3 por segmentos;
- encoding canônico v6;
- CLI com verificação de segmentos/Merkle;
- caminho de prova por LSN;
- validação de objetos cold contra recibo/raiz.

Arquivos relevantes incluem:

- `crates/heraclitus-log/src/lib.rs`;
- `crates/heraclitus-log/src/v6/canonical.rs`;
- `crates/heraclitus-log/src/v6/packer.rs`;
- `crates/heraclitus-cli/src/lib.rs`.

### Agent Gateway

Há implementação real para:

- gateway MCP;
- policy engine;
- identity handling;
- approval;
- rejeição de replay;
- contadores de gateway;
- observabilidade/red-team.

Arquivos/campanhas relevantes:

- `crates/heraclitus-agent-gateway/src/gateway.rs`;
- `crates/heraclitus-agent-gateway/src/runtime.rs`;
- `labs/Agent-Atack-Heraclitus/runner.py`;
- `labs/Agent-Atack-Heraclitus/runner_massive.py`.

A campanha existente já usa a ideia correta de oráculo independente: decisão do gateway + delta de hits no upstream.

### Compliance / timestamp

O código possui infraestrutura de RFC 3161, trust store e validação criptográfica em diferentes graus de maturidade.

O próprio STATUS do projeto deixa claro que confiança institucional real depende de âncoras instaladas pelo operador e qualificação externa.

## Capacidades que continuam Draft/Proposed

### SPEC-0087

`Forensic Evidence Package & Chain of Custody` permanece Draft/Proposed. A POC implementará um **subconjunto experimental POC**, não anunciará o pacote completo como produção.

### SPEC-0089

`Trusted Administration Protocol` permanece Draft/Proposed. A POC pode testar princípios de fail-closed/intent, mas não deve afirmar que o protocolo final está completo.

### SPEC-0086

HSM/PKCS#11 e KeyProvider governamental permanecem parte da evolução. HSM institucional não faz parte do P0.

## Supply chain existente

O repositório HeraclitusDB possui plano de qualificação governamental com referências a SBOM CycloneDX e verificação externa de artefatos. A POC deve reutilizar conceitos e não inventar um segundo modelo incompatível.

## Regra de atualização

Antes da reunião:

1. fixar commit exato do HeraclitusDB;
2. atualizar este documento;
3. executar qualification;
4. registrar mudanças de capacidade;
5. impedir que README/apresentação aleguem feature ausente no commit fixado.
