@echo off
echo ========================================================
echo   Iniciando Dashboard POC STF / HeraclitusDB (Loopback)
echo ========================================================
echo Acesse: http://127.0.0.1:8787
echo Pressione Ctrl+C para encerrar.
echo.

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py poc\server.py %*
) else (
    python poc\server.py %*
)
