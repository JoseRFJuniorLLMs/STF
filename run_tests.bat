@echo off
echo ========================================================
echo   Executando Testes e Qualificacao da POC STF
echo ========================================================
echo.

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set PYCMD=py
) else (
    set PYCMD=python
)

echo [1/3] Compilando arquivos Python...
%PYCMD% -m py_compile poc\server.py poc\verify.py poc\heraclitus_adapter.py poc\telemetry.py poc\correlation.py poc\detector.py poc\policy.py poc\faults.py poc\smoke.py poc\synthetic_upstream.py
if %ERRORLEVEL% neq 0 (
    echo [FALHA] Erro na compilacao dos arquivos Python.
    exit /b %ERRORLEVEL%
)

echo [2/3] Executando 80 testes unitarios...
%PYCMD% -m unittest discover -s poc\tests -v
if %ERRORLEVEL% neq 0 (
    echo [FALHA] Falha nos testes unitarios.
    exit /b %ERRORLEVEL%
)

echo [3/3] Executando Smoke Test HTTP em loopback...
%PYCMD% poc\smoke.py
if %ERRORLEVEL% neq 0 (
    echo [FALHA] Falha no teste HTTP smoke.
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   TODOS OS TESTES E QUALIFICACOES PASSARAM COM SUCESSO!
echo ========================================================
