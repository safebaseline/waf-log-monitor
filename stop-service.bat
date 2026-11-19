@echo off
cd /d %~dp0
set PID=
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8686 ^| findstr LISTENING') do set PID=%%a
if not "%PID%"=="" (
  taskkill /F /PID %PID%
  echo Service stopped. PID: %PID%
) else (
  echo No process listening on 8686.
)
ping -n 3 127.0.0.1 >nul
exit
