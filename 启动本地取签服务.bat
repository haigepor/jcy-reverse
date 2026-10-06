@echo off
setlocal
cd /d "%~dp0"
title JCY local auth service (127.0.0.1:8791)
echo ============================================================
echo  JCY (Jiongciyuan)  local auth / decrypt service
echo ------------------------------------------------------------
echo  Apipost PRE  script calls this service to get fresh
echo                ts + authentication + encrypted request body.
echo  Apipost POST script calls this service to decrypt responses.
echo.
echo  USAGE: keep this window OPEN, then click Send in Apipost.
echo         Ready when you see: authgen service started
echo  STOP : close this window, or press Ctrl+C
echo ============================================================
echo.
set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" (
  echo [ERROR] .venv python not found: %PY%
  echo         run: python -m venv .venv
  pause
  exit /b 1
)
"%PY%" research\deliverables\authgen_server.py --warmup
echo.
echo [service exited] Press any key to close...
pause >nul
