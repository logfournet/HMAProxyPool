@echo off
cd /d "%~dp0"
echo == HMAProxyPool build (Windows) ==
go build -o hmaproxypool.exe .
if errorlevel 1 goto :fail
echo == building hmatoken.exe (optional: Windows live token import) ==
go build -o hmatoken.exe ./tools/hmatoken 2>nul
if errorlevel 1 echo (hmatoken skipped)
echo.
echo Built: hmaproxypool.exe
echo Run:  hmaproxypool.exe   (opens http://127.0.0.1:8899)
goto :eof
:fail
echo BUILD FAILED
exit /b 1
