# EZWinBan
EZWinBan builds on and automates [Nathan Studebaker's](https://blog.watchpointdata.com/author/nathan-studebaker) brute force attack detection and blacklisting on Windows Server with powershell script. See: https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell. Like Fail2Ban or DenyHosts, but for Microsoft Windows.

My driver behind enhancing this script (and building an easy to use installer with InnoSetup) was preventing AD account lockouts (EventCode 4740) due to brute force or purposeful denial of service attacks against known AD accounts. It has proven to be quite effective for this task.

EZWinBan is a Powershell script that is triggered via Scheduled Task. It parses events (code 4740) from the Windows "Security" log every 5 minutes, extracts the IP address from each event, counts the number of login failures from each IP, notes any that are over the threshold, checks IPs against the whitelist, and adds offending IP addresses to the scope of a Windows firewall rule. History and expiry is maintained in text files; once daily, IPs whose bans have expired are removed (based on the contents of the historical text files).


## Features
* Easy to get started - run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/1.0.0/EZWinBan-Install.exe) and begin banning problematic IPs in seconds
* Works on Windows Server 2008+
* Automatically ban IPs that repeatedly fail to login to various Microsoft services (anything that logs EventCode 4740 to the "Security" log upon login failure) - examples include: IIS virtual SMTP server, Remote Desktop Services (RDS/RDP), SMB/CIFS, Active Directory Federation Services (ADFS), etc.
* Configurable settings: ban time (how long IPs remain banned), number of authentication failures resulting in a ban
* Ability to whitelist IPs and/or subnets
* Tiny foot print - less than 1 MB installed
* Simple solution - easy to understand and customize (based on built-in Windows components like PowerShell, Windows Firewall, and Task Scheduler)


## Usage
* Download and run the [installer](https://github.com/neil-sabol/EZWinBan/releases/download/1.0.0/EZWinBan-Install.exe) - this creates a EZWinBan folder in %programfiles%, a firewall rule that EZWinBan will manipulate, and a Scheduled Task that runs EZWinBan (process.ps1).

**That is basically it for basic usage. I highly recommend reviewing the following to fine tune EZWinBan though.**

* Additional configuration is possible using the files in %programfiles%\EZWinBan\config
     * settings.ini: Configure how long IPs remain banned AND how many failed login attempts trigger a ban
     * whitelist.txt: Add IP addresses and/or subnets that should never be banned - see comments in the file for formatting
   
* EZWinBan runs every 5 minutes by default (via Scheduled Task) - wait ~5 minutes and check %programfiles%\EZWinBan\work and you should see a "work file" created and named after the current date. That indicates that EZWinBan is being executed properly. If you open Windows Firewall and access the rule called "EZWinBan," you should see IP addresses under the Scope tab that match those written to the work file.

* To remove EZWinBan, simply uninstall it from Apps or Programs and Features

* You can customize/rebuild the EZWinBan installer as needed using [Inno Setup](http://www.jrsoftware.org/) and the included .iss file.


## Acknowledgements
[Nathan Studebaker](https://blog.watchpointdata.com/author/nathan-studebaker): [RDP Brute Force Attack Detection and Blacklisting with Powershell](https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell) - Genius approach and implementation to Powershell-based event log (EventCode 4740) analysis and lockout (Windows firewall).

[Joel Sallow](https://www.reddit.com/user/Ta11ow/): [Check a list of IP's against a list of subnets](https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/) - quick and easy ip/subnet comparison code (Powershell).

[Jordan Russell and Martijn Laan](http://www.jrsoftware.org/isinfo.php): [Inno Setup](http://www.jrsoftware.org/) - Best installer creation tool ever!

Others, as cited inline in *process.ps1*


