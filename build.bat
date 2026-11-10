@echo off
cd /d "%~dp0"
echo == HMAProxyPool build (Windows) ==
REM -trimpath keeps local paths out of the binary, -s -w drops debug info.
go build -trimpath -ldflags "-s -w" -o hmaproxypool.exe .
if errorlevel 1 goto :fail
echo == building hmatoken.exe (optional: Windows live token import) ==
go build -trimpath -ldflags "-s -w" -o hmatoken.exe ./tools/hmatoken 2>nul
if errorlevel 1 echo (hmatoken skipped)
echo.
echo Built: hmaproxypool.exe
echo Run:  hmaproxypool.exe   (opens http://127.0.0.1:8899)
goto :eof
:fail
echo BUILD FAILED
exit /b 1