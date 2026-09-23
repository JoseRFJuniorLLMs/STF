# SPEC-0027 — STF Public Environment Approximation Profile

**Status:** Proposed  
**Classe:** Environment Profile  
**Prioridade:** P0  
**Dependências:** pesquisa pública

## 1. Objetivo

Orientar fixtures e componentes da POC com base em classes de tecnologia publicamente documentadas pelo STF, sem reconstruir topologia sensível.

## 2. Classes confirmadas publicamente

- sistemas judiciais/STF Digital;
- peticionamento eletrônico;
- MNI;
- SEI;
- sistemas corporativos;
- data center;
- AI servers/HPC;
- Linux;
- VDI/Windows desktop;
- LAN/WLAN;
- backup/data protection;
- data warehouse/lake/marts;
- BI;
- dev tooling;
- IA jurisdicional.

## 3. Perfil sintético

```yaml
profile: stf-public-approx-v1
edge:
  firewall: vendor-neutral
  waf: vendor-neutral
identity:
  provider: vendor-neutral
compute:
  linux: true
  windows: true
  ai_hpc_class: true
network:
  lan_wlan: true
data:
  transactional_db: engine-neutral
  warehouse_lake: true
applications:
  judicial_app: synthetic
  admin_sei_like: synthetic
  mni_like_integration: synthetic
ai:
  local_ai_workload_class: true
protection:
  backup_appliance_class: true
```

## 4. Não inferir

Não fixar vendor atual de firewall, WAF, SIEM, EDR, banco, hypervisor, storage ou IAM sem fonte oficial atual.

## 5. Fontes

Consultar `docs/STF-PUBLIC-INFRA-BASELINE.md`.

## 6. Atualização

Antes da apresentação, revisar fontes oficiais e registrar:

- date_checked;
- source;
- class;
- confidence;
- whether it changes POC fixture.

A POC deve continuar funcionando mesmo que um vendor real seja diferente, porque os contratos são por classe e adapter.
