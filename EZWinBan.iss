; Set variables containing basic EzWinBan information
#define AppName "EZWinBan"
#define AppVer "3.1"

[Setup]
AppName = {#AppName}
AppVerName = {#AppName} {#AppVer}
AppPublisher = Neil Sabol and others
AppVersion = {#AppVer}
DefaultDirName = {commonpf}\{#AppName}
; Place the generated installer on the current user's desktop
OutputDir=userdocs:..\Desktop
OutputBaseFilename={#AppName}-Install
DisableDirPage=yes
DisableProgramGroupPage=yes
Compression = lzma
SolidCompression = yes
; I am referencing %programfiles% throughout (in the PowerShell script and scheduled task.
; This ensures %programfiles% points to the "real" folder (not x86) on 64-bit systems.
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired = admin
; Suppressing warning since this app can/should only be installed once
MissingRunOnceIdsWarning = no

[Messages]
FinishedLabelNoIcons=Setup has finished installing [name].%n%nConsider adding your IP address and trusted subnets to the whitelist (%program files%\{#AppName}\config\whitelist.txt) to prevent unintended IP bans.

[Files]
Source: "*"; Excludes: "*.iss,*.md,*Tests.ps1,*.bak,LICENSE"; Flags: recursesubdirs createallsubdirs; DestDir: "{commonpf}\{#AppName}"

[Run]
; Disable Network Level Authentication (NLA) for Remote Desktop
Filename: "reg.exe"; Parameters: "add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"" /v UserAuthentication /t REG_DWORD /d 0 /f"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Disabling NLA for RDP
; Create new Windows Event Log using PowerShell
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""New-EventLog -LogName {#AppName} -Source ""{#AppName}"""""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating Event Log
; Create the Windows firewall rule that this app will add/remove IP addresses from
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#AppName}"" dir=in action=block enable=yes remoteip=255.255.255.254 profile=any"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating firewall rule
; Import the Scheduled Task that ensures the PowerShell script is running every minute
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Register-ScheduledTask -Xml (get-content '{commonpf}\{#AppName}\config\support\{#AppName}-Task.xml' -raw) -TaskName ""{#AppName}"""""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating scheduled task
; Configure required logging
Filename: "auditpol.exe"; Parameters: "/set /category:""Logon/Logoff"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging
Filename: "auditpol.exe"; Parameters: "/set /category:""Account Logon"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging
; Log installation event to Windows Event Log using PowerShell
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Write-EventLog -LogName {#AppName} -Source ""{#AppName}"" –EntryType Information –EventID 0 –Message '{#AppName} {#AppVer} installed'"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Logging install event

[UninstallRun]
; Remove the scheduled task
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Unregister-ScheduledTask -Confirm:$false -TaskName ""{#AppName}"""""; Flags: shellexec waituntilterminated runhidden
; Kill the running PowerShell process
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Get-Process -Id $(Get-Content '{commonpf}\{#AppName}\pid') | Stop-Process -Force"""; Flags: shellexec waituntilterminated runhidden
; Remove the Windows Event Log
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""Remove-EventLog -LogName ""{#AppName}"""; Flags: shellexec waituntilterminated runhidden
; Remove the Windows firewall rule
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#AppName}"""; Flags: shellexec waituntilterminated runhidden
; Remove remaining folder in Program Files
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy ByPass -Command ""sleep 15;Remove-Item -Path '{commonpf}\{#AppName}' -Recurse -Force"""; Flags: shellexec runhidden

