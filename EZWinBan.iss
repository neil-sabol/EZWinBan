[Setup]
AppName = EZWinBan
AppVerName = EZWinBan 2.1
AppPublisher = Neil Sabol and others
AppVersion = 2.1
DefaultDirName = {pf}\EZWinBan
; Place the generated installer on the current user's desktop
OutputDir=userdocs:..\Desktop
OutputBaseFilename=EZWinBan-Install
DisableDirPage=yes
DisableProgramGroupPage=yes
Compression = lzma
SolidCompression = yes
; I am referencing %programfiles% throughout (in the powershell script and scheduled task.
; This ensures %programfiles% points to the "real" folder (not x86) on 64-bit systems.
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired = admin

[Messages]
FinishedLabelNoIcons=Setup has finished installing [name].%n%nConsider adding your IP address and trusted subnets to the whitelist (%program files%\EZWinBan\config\whitelist.txt) to prevent unintended IP bans.

[Files]
Source: "*"; Excludes: "*.iss,*.md,.gitignore"; Flags: recursesubdirs createallsubdirs; DestDir: "{pf}\EZWinBan"

[Run]
; Disable Network Level Authentication (NLA) for Remote Desktop
Filename: "reg.exe"; Parameters: "add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"" /v UserAuthentication /t REG_DWORD /d 0 /f"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Disabling NLA for RDP
; Create new Windows Event Log for EZWinBan using powershell
Filename: "powershell.exe"; Parameters:  "-ExecutionPolicy ByPass -Command ""New-EventLog -LogName Application -Source ""EZWinBan"""""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating Event Log
; Create the Windows firewall rule that EZWinBan will add/remove IP addresses from
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""EZWinBan"" dir=in action=block enable=yes remoteip=255.255.255.254 profile=any"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating firewall rule
; Import the Scheduled Task that ensures the EZWinBan powershell script is running every minute
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Register-ScheduledTask -Xml (get-content '{pf}\EZWinBan\config\support\EZWinBan-Task.xml' -raw) -TaskName ""EZWinBan"""""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating scheduled task
; Configure logging to support EZWinBan
Filename: "auditpol.exe"; Parameters: "/set /category:""Logon/Logoff"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging
Filename: "auditpol.exe"; Parameters: "/set /category:""Account Logon"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging

[UninstallRun]
; Remove the scheduled task
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Unregister-ScheduledTask -Confirm:$false -TaskName ""EZWinBan"""""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Removing scheduled task
; Kill the PowerShell process running EZWinBan
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Get-Process -Id $(Get-Content '{pf}\EZWinBan\work\pid') | Stop-Process -Force"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Stopping EZWinBan PowerShell process
; Remove the Windows Event Log
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Remove-EventLog -Source ""EZWinBan"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Removing Event Log
; Remove the firewall rule
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""EZWinBan"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Removing firewall rule
; Remove remaining folder in Program Files (includes leftover pid and work files)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""sleep 15;Remove-Item -Path '{pf}\EZWinBan' -Recurse -Force"""; Flags: shellexec runhidden; StatusMsg: Removing remaining pid and work files
