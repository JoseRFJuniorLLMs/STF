@echo off
echo ========================================================
echo   Iniciando Dashboard POC STF / HeraclitusDB (Loopback)
echo ========================================================
echo Acesse: http://127.0.0.1:8787
echo Pressione Ctrl+C para encerrar.
echo.

if "%HERACLITUS_URL%"=="" (
    set HERACLITUS_URL=http://127.0.0.1:8080
    echo [WSL Bridge] HERACLITUS_URL configurado automaticamente para http://127.0.0.1:8080 (WSL Linux)
) else (
    echo [WSL Bridge] Usando HERACLITUS_URL=%HERACLITUS_URL%
)
echo.

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py poc\server.py %*
) else (
    python poc\server.py %*
)
