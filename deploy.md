# Atualização da demonstração STF na GCP

Ambiente verificado em 24/09/2026:

| Item | Valor |
| --- | --- |
| Projeto GCP | `memoria-499818` |
| VM | `memoria-vm-2` |
| Zona | `southamerica-east1-a` |
| IP público | `35.247.217.66` |
| Usuário SSH | `web2a` (configurado pelo `gcloud compute ssh`) |
| Código na VM | `/home/web2a/STF` |
| Serviço | `stf-dashboard.service` |
| Servidor | `127.0.0.1:8787` atrás do Nginx em `/stf/` |
| Ledger | HeraclitusDB local em `127.0.0.1:8080` |

O acesso SSH direto via `gcloud compute ssh` funciona com a conta GCP já autenticada nesta máquina. O túnel IAP não é necessário e a conta atual não possui a permissão `iap.tunnelInstances.accessViaIAP`.

## 1. Validar localmente

No PowerShell, em `D:\DEV\STF`:

```powershell
$GCloudExe = 'C:\Users\web2a\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
$PythonExe = 'C:\Users\web2a\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $PythonExe -m unittest discover -s poc/tests -q
node --check poc/dashboard/app.js
node --check poc/dashboard/incidente.js
git diff --check
```

## 2. Conferir e fazer backup na VM

```powershell
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='git -C /home/web2a/STF status --short'
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='mkdir -p /home/web2a/backups && tar -czf /home/web2a/backups/stf-before-demo-update.tgz -C /home/web2a/STF poc/server.py poc/dashboard poc/README.md'
```

Confirme que o `git status --short` não mostra alterações inesperadas antes de copiar arquivos. O backup preserva a versão anterior do servidor, do front e da documentação.

## 3. Copiar os arquivos alterados

Execute em `D:\DEV\STF`:

```powershell
$Files = @(
  'deploy.md',
  'poc/README.md',
  'poc/server.py',
  'poc/dashboard/app.js',
  'poc/dashboard/incidente.js',
  'poc/dashboard/index.html',
  'poc/dashboard/styles.css',
  'poc/tests/test_poc.py'
)
foreach ($File in $Files) {
  $LocalFile = Join-Path (Get-Location) $File
  $Content = [System.IO.File]::ReadAllText($LocalFile)
  [System.IO.File]::WriteAllText($LocalFile, $Content.Replace("`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
  $RemoteFile = 'memoria-vm-2:/home/web2a/STF/' + $File
  & $GCloudExe compute scp $LocalFile $RemoteFile --project=memoria-499818 --zone=southamerica-east1-a
  if ($LASTEXITCODE -ne 0) { throw "Falha ao copiar $File" }
}
```

## 4. Testar e reiniciar

```powershell
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='cd /home/web2a/STF && python3 -m unittest discover -s poc/tests -q'
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='cd /home/web2a/STF && python3 -m py_compile poc/server.py && git diff --check'
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='sudo systemctl restart stf-dashboard.service && systemctl is-active stf-dashboard.service'
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='curl -fsS http://127.0.0.1:8787/api/health'
```

Abra a aba `#incidente` da publicação e confira as linhas **Defendidos**, **Bloqueados** e **Chegaram ao alvo**. Para disparar as tentativas, use **Simular rede** na aba Defesa cibernética. Cada grupo de dez tentativas por componente gera 6 defendidas, 3 bloqueadas e 1 que chegou ao alvo somente na simulação. Os eventos são gravados na campanha `STF-DEMO-SIMULATION`; o efeito real no alvo permanece zero.

## 5. Ajustar os percentuais

O padrão é 60/30/10. Para outro perfil, configure `STF_DEMO_DEFENDED_PCT`, `STF_DEMO_BLOCKED_PCT` e `STF_DEMO_TARGET_PCT` no ambiente do serviço `stf-dashboard.service`. Os três valores inteiros devem somar 100. Depois, reinicie o serviço. A configuração vale para novos eventos; não reescreve registros já gravados no ledger.

## 6. Reverter esta atualização

Se a validação falhar, restaure o backup feito no passo 2 e reinicie o serviço:

```powershell
& $GCloudExe compute ssh memoria-vm-2 --project=memoria-499818 --zone=southamerica-east1-a --command='tar -xzf /home/web2a/backups/stf-before-demo-update.tgz -C /home/web2a/STF && sudo systemctl restart stf-dashboard.service && systemctl is-active stf-dashboard.service'
```

Essa reversão restaura o código. Os eventos já gravados no HeraclitusDB permanecem no histórico.
