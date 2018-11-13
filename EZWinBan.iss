[Setup]
AppName = EZWinBan
AppVerName = EZWinBan 1.0
AppPublisher = Neil Sabol and others
AppVersion = 1.0
DefaultDirName = {pf}\EZWinBan
; Place the generated installer on the current user's desktop
OutputDir=userdocs:..\Desktop
OutputBaseFilename=EZWinBan-Install
DisableDirPage=yes
DisableProgramGroupPage=yes
Compression = lzma
SolidCompression = yes
; I am referencing %programfiles% throughout (in the powershell script and scheduled task.
; This ensures %programfiles% point to the "real" folder (not x86) on 64-bit systems.
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired = admin

[Messages]
FinishedLabelNoIcons=Setup has finished installing [name].%n%nConsider adding your IP address and trusted subnets to the whitelist (%program files%\EZWinBan\config\whitelist.txt) prior to enabling EZWinBan.

[Files]
Source: "*"; Excludes: "*.iss,\Output"; Flags: recursesubdirs createallsubdirs; DestDir: "{pf}\EZWinBan"

[Run]
; Disable Network Level Authentication (NLA) for Remote Desktop
Filename: "reg.exe"; Parameters: "add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"" /v UserAuthentication /t REG_DWORD /d 0 /f"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Disabling NLA for RDP
; Create the Windows firewall rule that EZWinBan will add/remove IP addresses from
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""EZWinBan"" dir=in action=block enable=yes remoteip=255.255.255.254 profile=any"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating firewall rule
; Import the Scheduled Task that runs the EZWinBan powershell script every 5 minutes
Filename: "schtasks.exe"; Parameters: "/Create /XML ""{app}\config\support\EZWinBan-Task.xml"" /TN ""EZWinBan"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Creating scheduled task
; Configure logging to support EZWinBan
Filename: "auditpol.exe"; Parameters: "/set /category:""Logon/Logoff"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging
Filename: "auditpol.exe"; Parameters: "/set /category:""Account Logon"" /success:enable /failure:enable"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Configuring logging

[UninstallRun]
; Since I do not capture the initial state of RDP NLA or logging settings, those are left as during uninstall
; Remove the firewall rule
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""EZWinBan"""; Flags: shellexec waituntilterminated runhidden; StatusMsg: Removing firewall rule
; Remove the scheduled task
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""EZWinBan"" /F"; Flags: shellexec waituntilterminated runhidden; StatusMsg: Removing scheduled task
