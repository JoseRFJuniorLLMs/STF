$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "STF POC / HeraclitusDB - http://127.0.0.1:8787"
python server.py --host 127.0.0.1 --port 8787
