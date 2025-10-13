@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set VENV_DIR=.venv
set PYTHON_EXE=
where py >nul 2>nul && set PYTHON_EXE=py -3
if "%PYTHON_EXE%"=="" where python >nul 2>nul && set PYTHON_EXE=python
if "%PYTHON_EXE%"=="" (
  echo Konnte keinen Python-Interpreter finden. Bitte Python 3 installieren.
  exit /b 1
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
  %PYTHON_EXE% -m venv "%VENV_DIR%"
  if errorlevel 1 (
    echo Fehler beim Erstellen der venv.
    exit /b 1
  )
)

call "%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
  echo Fehler beim Aktualisieren von pip.
  exit /b 1
)

if exist requirements.txt (
  call "%VENV_DIR%\Scripts\python.exe" -m pip install -r requirements.txt
) else (
  echo requirements.txt fehlt.
  exit /b 1
)

echo Starte MCP Diagnoser PRO (GUI)...
call "%VENV_DIR%\Scripts\python.exe" "mcp_diag_pro.py"
endlocal
