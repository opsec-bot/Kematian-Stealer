<p align="center">
<img src="https://i.postimg.cc/m2SSKrBt/Logo.gif", width="300", height="300">
</p>

<h1 align="center">
</h1>
<p align= "center">
  <img src="https://img.shields.io/github/languages/top/Chainski/Powershell-Token-Grabber">
   <img src="https://img.shields.io/github/stars/Chainski/Powershell-Token-Grabber.svg?color=yellow">
   <img src="https://img.shields.io/github/forks/Chainski/Powershell-Token-Grabber.svg?color=red">
   <img src="https://img.shields.io/github/issues/Chainski/Powershell-Token-Grabber.svg?color=green">
   <img src="https://img.shields.io/badge/dynamic/json?label=Visitors&query=value&url=https%3A%2F%2Fapi.countapi.xyz%2Fhit%2FChainski%2FPowershell-Token-Grabber">
   <br>
   <img src="https://img.shields.io/github/last-commit/Chainski/Powershell-Token-Grabber">
   <img src="https://img.shields.io/github/license/Chainski/Powershell-Token-Grabber">
    <img src="https://img.shields.io/github/repo-size/Chainski/Powershell-Token-Grabber.svg?label=Repo%20size&style=flat-square">
   <br>
</p>

# Powershell Token Grabber 

This tool is made for data exfiltration. All information collected is sent using discord webhooks.

# Usage

- Create a Webhook on your [Discord Server](https://discord.com). I recommend creating a new server.
- Replace YOUR_WEBHOOK_HERE in line 30 with your webhook.



# Want to obfuscate the code ?
Use [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation). 

# Screenshot

![preview](https://user-images.githubusercontent.com/96607632/218895849-08f2f5c7-ef6e-49e0-9e21-60f291e16c09.png)


#  Features
- [x] Persistence via [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler)
- [x] Extracts WiFi Passwords
- [x] Extracts Browser Data (Brave, Chrome, Firefox, Microsoft Edge etc.)
- [x] Extracts Discord Token
- [x] Extracts Discord Tokens
- [x] Get System Information (Version, CPU, DISK, GPU, RAM, IP, Installed Apps etc.)
- [x] Takes Desktop Screenshot  
- [x] List of Installed Applications
- [x] List of all Network Adapters
- [x] List of Apps that Run On Startup
- [x] List of Running Services & Applications
- [x] List TCP Connections and Underlying Process
- [x] Extracts Product Key
 
# Uninstaller (Removes the Scheduled Task and Script Folder)
- Open a new Elevated Powershell Console and Paste the Contents below
```
$ErrorActionPreference = "SilentlyContinue"
function Cleanup {
  Unregister-ScheduledTask -TaskName "KDOT" -Confirm:$False
  Remove-Item -Path "$env:appdata\KDOT" -force -recurse
  Write-Host "[~] Successfully Uninstalled !" -ForegroundColor Green
}
Cleanup
```

# Need Help?
- Join our server https://discord.com/invite/mdmtCTseNV

# License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/Chainski/Powershell-Token-Grabber/blob/main/LICENSE) file for details

# Disclaimer
I, the creator, am not responsible for any actions, and or damages, caused by this software.
You bear the full responsibility of your actions and acknowledge that this tool was created for educational purposes only.
This tool's main purpose is NOT to be used maliciously, or on any system that you do not own, or have the right to use.
By using this software, you automatically agree to the above.

## Donate 
<a href="https://www.blockchain.com/btc/address/16T1fUehoGR4E2sj98u9e9mKuQ7uSLvxRJ"><img src="https://img.shields.io/badge/bitcoin-donate-yellow.svg"></a>


# Credits
- https://github.com/Purp1eW0lf
- https://github.com/KDot227


