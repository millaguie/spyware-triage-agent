@echo off
rem Run the sta CLI from cmd.exe on Windows. PowerShell uses sta.ps1, Git Bash ./sta.
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo ERROR: %~dp0.venv is missing. Run install.ps1 first. 1>&2
  exit /b 2
)
set PYTHONUTF8=1
"%~dp0.venv\Scripts\python.exe" -m sta %*
exit /b %ERRORLEVEL%
