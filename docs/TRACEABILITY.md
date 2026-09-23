# Matriz de Rastreabilidade — STF POC HeraclitusDB

| Claim | SPEC | Teste | Evidência |
|---|---|---|---|
| modificação histórica é detectada | 0004 | INT-01 | root/digest mismatch |
| exclusão é detectada | 0004 | AC-03 | count/proof failure |
| replay temporal é determinístico | 0008 | AC-16 | equal state digest |
| HIGH exige HITL | 0005 | AC-06/07 | policy + approval |
| approval replay é bloqueado | 0005/0006 | ADV-01 | DENY + upstream_delta=0 |
| identity swap é bloqueado | 0005/0006 | ADV-03 | DENY |
| TOCTOU é bloqueado | 0005 | AC-19 | parameters digest mismatch |
| bundle verifica offline | 0007 | AC-12/28 | verifier output |
| bundle adulterado falha | 0007 | AC-13 | digest/Merkle failure |
| egress não é necessário | 0009 | AC-26 | network profile |
| build é identificável | 0015 | AC-25 | BUILD-INFO/SBOM |
| crash não inventa sucesso | 0017 | AC-24 | FAILED/UNKNOWN |
| claims têm limites | 0001/0012 | AC-29 | trust statuses |

## Regra

Nenhuma claim nova entra no README ou apresentação sem SPEC, teste, evidência e limitação quando aplicável.
