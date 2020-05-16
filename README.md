# EZWinBan
EZWinBan builds on and automates [Nathan Studebaker's](https://blog.watchpointdata.com/author/nathan-studebaker) brute force attack detection and blacklisting on Windows Server with PowerShell script. See https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell. Like Fail2Ban or DenyHosts, but for Microsoft Windows.

The driver behind enhancing Nathan's script (and building an easy to use installer with [InnoSetup](http://www.jrsoftware.org/isinfo.php)) is preventing AD account lockouts (EventCode 4740) due to brute force or purposeful denial of service attacks against known AD accounts. EZWinBan is quite effective for this task.

EZWinBan is a Powershell script that is triggered via Scheduled Task and runs in a loop. It parses events (code 4625) from the Windows "Security" log on a user-configurable interval (seconds), extracts the IP address from each event, counts the number of login failures from each IP, notes any that are over the threshold, checks IPs against the whitelist, and adds offending IP addresses to the scope of a Windows firewall rule. History and expiry are maintained in text files; hourly, IPs whose bans have expired are removed (based on the contents of the historical text files). EZWinBan logs basic events (banned and unbanned IPs) to the Windows Event Log (Log: Application, Source: EZWinBan).

Although EZWinBan is awesome, if you are looking for a more mature and robust approach to IP banning on Windows, [IPBan](https://github.com/DigitalRuby/IPBan) is worth a look.


## Features
* Easy to get started - run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/2.0.0/EZWinBan-Install.exe) and begin banning problematic IPs in seconds
* Based on Windows native components like PowerShell, Windows Firewall, and Task Scheduler
* Works on Windows Server 2008+ (2012+ highly recommended)
* Automatically ban IPs that repeatedly fail to log in to various Microsoft services (anything that logs EventCode 4625 to the "Security" log upon login failure) - examples include IIS virtual SMTP server, Remote Desktop Services (RDS/RDP), SMB/CIFS, etc.
* Configurable settings: ban time (how long IPs remain banned in hours), number of authentication failures resulting in a ban, period (interval) to "look back" for failed logins in the event log, logging to Event Log (on or off), execution speed (seconds to wait between "runs")
* Ability to whitelist IPs and/or subnets
* Tiny footprint - less than 1 MB installed
* Simple solution - easy to understand and customize


## Usage (basic)
* Download and run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/2.0.0/EZWinBan-Install.exe) - this creates an *EZWinBan* folder in %programfiles%, a firewall rule that EZWinBan will manipulate, and a Scheduled Task that ensures EZWinBan (process.ps1) is running.


## Usage (advanced)
* Additional configuration is possible using the files in %programfiles%\EZWinBan\config
     * settings.ini
          * How many HOURS IPs remain banned (**LOCKOUTDURATION**)
          * How many failed login attempts trigger a ban (**FAILEDLOGINTHRESHOLD**)
          * How many MINUTES EZWinBan "looks back" in the event log for failed logins (**LOGLOOKBACKINTERVAL**) - useful for "slow" attacks where login failures do not occur in a short interval
          * Should EZWinBan log bans (EventID 100) and unbans (EventID 101) to the Application Log (Windows Event Log) (**LOGGING**)
          * How many SECONDS EZWinBan waits between runs (**DELAY**) - the lower the DELAY, the faster EZWinBan runs and bans IPs (at the expense of CPU/memory/disk usage) - the higher the delay, the slower EZWinBan runs and bans IPs (reduces resource usage)
     * whitelist.txt
          * IP addresses and/or subnets that should never be banned - see comments in the file for formatting
   
* EZWinBan runs on the interval (seconds) specified by DELAY in settings.ini. To reduce the resources consumed by EZWinBan, set the DELAY higher (slows down the processing loop at the expense of how quickly offending IPs are banned). The Scheduled Task ensures EZWinBan is still running each 1 minute (if it is already running, no action is taken - if it is not running, the Scheduled Task starts it). If EZWinBan is being executed properly, check %programfiles%\EZWinBan\work and you should see a "work file" created and named after the current date and time. Banned IPs are written to the work files. If you open Windows Firewall and access the rule called "EZWinBan," you should see IP addresses under the Scope tab that match those written to the work file.

* To remove EZWinBan, simply uninstall it from Apps or Programs and Features. You may need to manually remove %programfiles%\EZWinBan after uninstallation (known issue).

* You can customize/rebuild the EZWinBan installer as needed using [Inno Setup](http://www.jrsoftware.org/) and the included .iss file.

* It is advisable to disable NTLM on your Windows servers as well (assuming you are not using it) - see [Network Security: Restrict NTLM: Incoming NTLM Traffic](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/jj852167(v=ws.10))


## Useful diagnostic commands
### Get a list of banned IPs from the firewall rule
```
((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq 'EZWinBan'}).remoteaddresses -split(',')
```

### Get a list of banned IPs from the work files
Should match "banned IPs from the firewall rule," minus 255.255.255.254/255.255.255.255 
```
get-content -path $env:programfiles'\EZWinBan\work\*.log' | Get-Unique
```

### Get the count of banned IPs from the firewall rule
If no IPs are banned this shows as 1 because of the "placeholder" IP, 255.255.255.254/255.255.255.255
```
((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq 'EZWinBan'}).remoteaddresses -split(',') | measure-object
```

### Get the count of banned IPs from the work files
Should match ("count of banned IPs from the firewall rules" - 1)
```
get-content -path $env:programfiles'\EZWinBan\work\*.log' | Get-Unique | measure-object
```

### List IPs with login failures from the Security event log for the last 15 minutes
```
Get-WinEvent -FilterHashtable @{LogName="Security";ID="4625";StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data[19] } | select-object '#text'
```

### Show top /8 subnets blocked in the firewall rule
```
$blockedIPs=((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq 'EZWinBan'}).remoteaddresses -split(',')
$blockedIPs.split(".",2) | where-object {!($_.contains("."))} | group-object | sort-object
```


## Limitations, issues and "to do"
* The banned IP expiry interval is in hours (not minutes, etc.) - the minimum amount of time an IP can be banned is 1 hour. To ban IPs for days, provide the value in hours ( days * 24 )
* The tracking of banned IPs needs to be improved so they are unbanned (expire) predictably and consistently
* The work file expiry interval should be made configurable (instead of 15 minutes hard-coded)
* Logging needs to be improved, for example: log whitelisted IPs with failed logins, log major errors/issues, implement different logging levels like DEBUG, INFO, ERROR
* The uninstaller needs fixed so that the EZWinBan directory (under Program Files), work directory and child files are removed during uninstall


## Acknowledgements
[Nathan Studebaker](https://blog.watchpointdata.com/author/nathan-studebaker): [RDP Brute Force Attack Detection and Blacklisting with Powershell](https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell) - Genius approach and implementation to Powershell-based event log (EventCode 4740) analysis and lockout (Windows firewall).

[Joel Sallow](https://www.reddit.com/user/Ta11ow/): [Check a list of IP's against a list of subnets](https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/) - quick and easy IP/subnet comparison code (Powershell).

[Jordan Russell and Martijn Laan](http://www.jrsoftware.org/isinfo.php): [Inno Setup](http://www.jrsoftware.org/) - Best installer creation tool ever!

Others, as cited inline in *process.ps1*
