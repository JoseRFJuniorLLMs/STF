# Deploy reproduzível da demonstração STF na GCP

A VM pública deve executar **um commit Git exato**. O procedimento de copiar uma lista manual de arquivos foi removido porque permitia que a VM divergisse do GitHub.

## Ambiente

| Item | Valor |
| --- | --- |
| Projeto GCP | `memoria-499818` |
| VM | `memoria-vm-2` |
| Zona | `southamerica-east1-a` |
| Código na VM | `/home/web2a/STF` |
| Serviço | `stf-dashboard.service` |
| Aplicação | `127.0.0.1:8787` atrás do Nginx em `/stf/` |

As configurações efetivas de Nginx e systemd devem ser versionadas antes de uma qualificação institucional.

## 1. Qualificar localmente

```powershell
python -m compileall -q poc zera.py
python -m unittest discover -s poc/tests -v
python poc/smoke.py
Get-ChildItem poc/dashboard/*.js | ForEach-Object { node --check $_.FullName }
git diff --check
```

## 2. Escolher o SHA

```powershell
$Sha = git rev-parse HEAD
if (-not $Sha) { throw "SHA local não encontrado" }
if (git status --porcelain) { throw "Working tree local não está limpa" }
```

## 3. Backup e checkout por SHA

```powershell
$GCloudExe = 'C:\Users\web2a\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
$Remote = @"
set -euo pipefail
cd /home/web2a/STF
test -z "$(git status --porcelain)"
PREV=$(git rev-parse HEAD)
mkdir -p /home/web2a/backups
tar -czf /home/web2a/backups/stf-${PREV}.tgz .
git fetch --prune origin
git cat-file -e ${Sha}^{commit}
git checkout --detach ${Sha}
python3 -m compileall -q poc zera.py
python3 -m unittest discover -s poc/tests -q
python3 poc/smoke.py
for file in poc/dashboard/*.js; do node --check "$file"; done
sudo systemctl restart stf-dashboard.service
systemctl is-active --quiet stf-dashboard.service
curl -fsS http://127.0.0.1:8787/api/health
echo DEPLOYED_SHA=$(git rev-parse HEAD)
"@
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command=$Remote
```

O valor de `DEPLOYED_SHA` deve ser exatamente o SHA qualificado pelo CI.

## 4. Smoke público

Validar: `#processos`, `#logvisual`, `#zanin` (**Forense de IA**), `#incidente`, `#auditoria`, `#resiliencia` e `#interoperabilidade`.

## 5. Rollback

```powershell
$RollbackSha = '<SHA_ANTERIOR>'
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command="cd /home/web2a/STF && git fetch origin && git checkout --detach $RollbackSha && python3 -m unittest discover -s poc/tests -q && sudo systemctl restart stf-dashboard.service && systemctl is-active stf-dashboard.service"
```

O rollback do código não reescreve eventos já persistidos no HeraclitusDB.
