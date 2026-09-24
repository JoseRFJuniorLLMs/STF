@echo off
cd /d "%~dp0"
echo STF POC / HeraclitusDB - http://127.0.0.1:8787
where py >nul 2>nul
if %errorlevel%==0 (
  py server.py --host 127.0.0.1 --port 8787
) else (
  python server.py --host 127.0.0.1 --port 8787
)
