# EZWinBan
EZWinBan builds on and automates [Nathan Studebaker's](https://blog.watchpointdata.com/author/nathan-studebaker) brute force attack detection and blacklisting on Windows Server with powershell script. See: https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell. Like Fail2Ban or DenyHosts, but for Microsoft Windows.

My driver behind enhancing this script (and building an easy to use installer with [InnoSetup](http://www.jrsoftware.org/isinfo.php)) was preventing AD account lockouts (EventCode 4740) due to brute force or purposeful denial of service attacks against known AD accounts. It has proven to be quite effective for this task.

EZWinBan is a Powershell script that is triggered via Scheduled Task. It parses events (code 4625) from the Windows "Security" log every 1 minute, extracts the IP address from each event, counts the number of login failures from each IP, notes any that are over the threshold, checks IPs against the whitelist, and adds offending IP addresses to the scope of a Windows firewall rule. History and expiry is maintained in text files; once daily, IPs whose bans have expired are removed (based on the contents of the historical text files).

Although EZWinBan is awesome, if you are looking for a more mature and robust approach to IP banning on Windows, [IPBan](https://github.com/DigitalRuby/IPBan) is worth a look.


## Features
* Easy to get started - run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/1.1.0/EZWinBan-Install.exe) and begin banning problematic IPs in seconds
* Works on Windows Server 2008+
* Automatically ban IPs that repeatedly fail to login to various Microsoft services (anything that logs EventCode 4625 to the "Security" log upon login failure) - examples include: IIS virtual SMTP server, Remote Desktop Services (RDS/RDP), SMB/CIFS, etc.
* Configurable settings: ban time (how long IPs remain banned), number of authentication failures resulting in a ban, time span (interval) to "look back" for failed logins in the event log
* Ability to whitelist IPs and/or subnets
* Tiny foot print - less than 1 MB installed
* Simple solution - easy to understand and customize (based on built-in Windows components like PowerShell, Windows Firewall, and Task Scheduler)


## Usage (basic)
* Download and run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/1.0.0/EZWinBan-Install.exe) - this creates a EZWinBan folder in %programfiles%, a firewall rule that EZWinBan will manipulate, and a Scheduled Task that runs EZWinBan (process.ps1).


## Usage (advanced)
* Additional configuration is possible using the files in %programfiles%\EZWinBan\config
     * settings.ini
          * How many DAYS IPs remain banned (LOCKOUTDURATION)
          * How many failed login attempts trigger a ban (FAILEDLOGINTHRESHOLD)
          * How many MINUTES EZWinBan "looks back" in the event log for failed logins (LOGLOOKBACKINTERVAL) - useful for "slow" attacks where login failures do not occur within the 1 minute intervals that EZWinBan runs
     * whitelist.txt
          * Add IP addresses and/or subnets that should never be banned - see comments in the file for formatting
   
* EZWinBan runs every 1 minute by default (via Scheduled Task) - wait ~1 minute and check %programfiles%\EZWinBan\work and you should see a "work file" created and named after the current date. That indicates that EZWinBan is being executed properly. If you open Windows Firewall and access the rule called "EZWinBan," you should see IP addresses under the Scope tab that match those written to the work file.

* To remove EZWinBan, simply uninstall it from Apps or Programs and Features.

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


## Limitations and To Do
* Banned IP expiry interval is in days only (not hours, minutes, etc.)
* Banned IP expiry is calendar day based and not based on when IPs are banned. For example, if an IP is banned at 11:59 PM, it could be unbanned at 12:00 AM (technially the next day but only 1 minute later)
* No history or logging, except the work files (which are deleted as bans expire)


## Acknowledgements
[Nathan Studebaker](https://blog.watchpointdata.com/author/nathan-studebaker): [RDP Brute Force Attack Detection and Blacklisting with Powershell](https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell) - Genius approach and implementation to Powershell-based event log (EventCode 4740) analysis and lockout (Windows firewall).

[Joel Sallow](https://www.reddit.com/user/Ta11ow/): [Check a list of IP's against a list of subnets](https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/) - quick and easy ip/subnet comparison code (Powershell).

[Jordan Russell and Martijn Laan](http://www.jrsoftware.org/isinfo.php): [Inno Setup](http://www.jrsoftware.org/) - Best installer creation tool ever!

Others, as cited inline in *process.ps1*


