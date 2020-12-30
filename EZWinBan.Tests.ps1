# ###############################
# EZWinBan
# https://github.com/neil-sabol/EZWinBan
# Neil Sabol
# neil.sabol@gmail.com
# ###############################

# Ensure tests are running as admin
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
    write-host ""
    write-host "These tests must be run in an elevated (administrator) PowerShell session."
    write-host "Please re-launch PowerShell as administrator and try again."
    write-host ""
    exit
}

# Ensure the Innosetup console-mode compiler is present in the standard location
if( -not (Test-Path -Path "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")) {
    write-host ""
    write-host "These tests require the InnoSetup console-mode compiler."
    write-host "Please install InnoSetup with the console-mode compiler"
    write-host "(ISCC.exe) and try again."
    write-host ""
    exit
}

# Capture the path the project and tests reside in
$script:currentPath = (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Define test parameters and scenarios
$script:appName = "EZWinBan"
$script:installerName = "$appName-Install.exe"
$script:installPath = "$env:ProgramW6432"
$script:testBadIP1 = "10.10.10.8"
$script:testBadIP2 = "10.10.10.9"
$script:testBadIP3 = "10.10.10.10"
$script:testWhitelistedIP = "127.0.0.1"
$script:testLOCKOUTDURATION = "5"
$script:testFAILEDLOGINTHRESHOLD = "3"
$script:testLOGLOOKBACKINTERVAL = "5"
$script:testDELAY = "1"
$script:testUNBANINTERVAL = "1"

# This should use mocking in Pester (someday), but for now, create fake Event Logs
# and functions to populate them with fake events that EZWinBan will process. This uses
# Kevin Holman's ingenious approach:
# https://kevinholman.com/2016/04/02/writing-events-with-parameters-using-powershell/
New-EventLog -LogName "FAKESecurity" -Source "FAKESecurity"

function CreateFAKESecurityEvent ($sourceIP) {
    $id = New-Object System.Diagnostics.EventInstance(4625,1);
    $evtObject = New-Object System.Diagnostics.EventLog;
    $evtObject.Log = "FAKESecurity";
    $evtObject.Source = "FAKESecurity";
    $evtObject.WriteEvent($id, @("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", $sourceIP))
}

# Begin Pester tests
Describe 'EZWinBan' {
    BeforeAll {
        # Backup EZWinBan.iss and update it so the firewall rule is created in a disabled state
        Copy-Item "$currentPath\EZWinBan.iss" -Destination "$currentPath\EZWinBan.iss.bak" -Force
        ((Get-Content -Path "$currentPath\EZWinBan.iss" -Raw) -replace 'enable=yes','enable=no') | Set-Content -Path "$currentPath\EZWinBan.iss"
        
        # Backup settings.ini and update it with more aggressive settings
        Copy-Item "$currentPath\config\settings.ini" -Destination "$currentPath\config\settings.ini.bak" -Force
        ((Get-Content -Path "$currentPath\config\settings.ini" -Raw) -replace 'LOCKOUTDURATION=30',"LOCKOUTDURATION=$testLOCKOUTDURATION") | Set-Content -Path "$currentPath\config\settings.ini"
        ((Get-Content -Path "$currentPath\config\settings.ini" -Raw) -replace 'FAILEDLOGINTHRESHOLD=3',"FAILEDLOGINTHRESHOLD=$testFAILEDLOGINTHRESHOLD") | Set-Content -Path "$currentPath\config\settings.ini"
        ((Get-Content -Path "$currentPath\config\settings.ini" -Raw) -replace 'LOGLOOKBACKINTERVAL=15',"LOGLOOKBACKINTERVAL=$testLOGLOOKBACKINTERVAL") | Set-Content -Path "$currentPath\config\settings.ini"
        ((Get-Content -Path "$currentPath\config\settings.ini" -Raw) -replace 'DELAY=5',"DELAY=$testDELAY") | Set-Content -Path "$currentPath\config\settings.ini"
        ((Get-Content -Path "$currentPath\config\settings.ini" -Raw) -replace 'UNBANINTERVAL=2',"UNBANINTERVAL=$testUNBANINTERVAL") | Set-Content -Path "$currentPath\config\settings.ini"

        # Backup process.ps1 and replace event log monitoring with fake logs
        Copy-Item "$currentPath\process.ps1" -Destination "$currentPath\process.ps1.bak" -Force
        ((Get-Content -Path "$currentPath\process.ps1" -Raw) -replace '\| Select-Object -ExpandProperty "#text"','') | Set-Content -Path "$currentPath\process.ps1"
        ((Get-Content -Path "$currentPath\process.ps1" -Raw) -replace 'LogName="Security"','LogName="FAKESecurity"') | Set-Content -Path "$currentPath\process.ps1"
    }
    Context "Innosetup Installer" {
        It "Should compile without major errors" {
            { Start-Process -Wait -WindowStyle Hidden -FilePath "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" -ArgumentList "`"$currentPath\EZWinBan.iss`"" } | Should -Not -Throw
        }
        It "Should create installer on desktop" {
            "$env:USERPROFILE\Desktop\$installerName" | Should -Exist
        }
        It "Should execute silently without errors" {
            { Start-Process -Wait -WindowStyle Hidden -FilePath "$env:USERPROFILE\Desktop\$installerName" -ArgumentList "/VERYSILENT" } | Should -Not -Throw
        }
        It "Should create folder under Program Files" {
            "$installPath\$appName" | Should -Exist
        }
        It "Should create EZWinBan-Task.xml file" {
            "$installPath\$appName\config\support\EZWinBan-Task.xml" | Should -Exist
        }
        It "Should create settings.ini file" {
            "$installPath\$appName\config\settings.ini" | Should -Exist
        }
        It "Should create whitelist.txt file" {
            "$installPath\$appName\config\whitelist.txt" | Should -Exist
        }
        It "Should create process.ps1" {
            "$installPath\$appName\process.ps1" | Should -Exist
        }
        It "Should not create README" {
            "$installPath\$appName\README.md" | Should -Not -Exist
        }
        It "Should not create LICENSE" {
            "$installPath\$appName\LICENSE" | Should -Not -Exist
        }
        It "Should not create EZWinBan.Tests.ps1" {
            "$installPath\$appName\EZWinBan.Tests.ps1" | Should -Not -Exist
        }
        It "Should not create a EZWinBan.iss" {
            "$installPath\$appName\EZWinBan.iss" | Should -Not -Exist
        }
        It "Should disable NLA for RDP" {
            (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication | Should -Be 0
        }
        It "Should create windows event log" {
            { Get-WinEvent -ListLog "$appName" -ErrorAction Stop } | Should -Not -Throw
        }
        It "Should create firewall rule" {
            $winFirewall = New-Object -ComObject hnetcfg.fwpolicy2
            ($winFirewall.rules | where {$_.name -eq "$appName" } | Measure-Object).Count | Should -Be 1
        }
        It "Should create scheduled task" {
            { Get-ScheduledTask -TaskName "$appName" -ErrorAction Stop } | Should -Not -Throw
        }
        It "Should set Logon/Logoff audit policy" {
            $auditPolicy = Invoke-Command -ScriptBlock { auditpol /get /category:"Logon/Logoff" }
            ($auditPolicy | where {$_ -like "*Success and Failure*" } | Measure-Object).Count | Should -Be 11
        }
        It "Should set Account Logon audit policy" {
            $auditPolicy = Invoke-Command -ScriptBlock { auditpol /get /category:"Account Logon" }
            ($auditPolicy | where {$_ -like "*Success and Failure*" } | Measure-Object).Count | Should -Be 4
        }
        It "Should log install event" {
            (Get-WinEvent -LogName "$appName" | where {$_.Id -eq 0 -and $_.Message -like "$appName * installed" } | Measure-Object).Count | Should -Be 1
        }
    }
    Context "Basic functionality" {
        It "Should create a pid file" {
            # It can take up to 1 minute for EZWinBan to start initially
            Sleep 60
            "$installPath\$appName\pid" | Should -Exist
        }
        It "Should be running with the pid written to the pid file" {
            (Get-Process -Id $(Get-Content "$installPath\$appName\pid")).Name | Should -Be "powershell"
        }
        It "Should log a startup event to the event log" {
            (Get-WinEvent -LogName "$appName" | where {$_.Id -eq 10 -and $_.Message -like "$appName * started with PID *" } | Measure-Object).Count | Should -Be 1
        }
        It "Should create a lastrun file" {
            "$installPath\$appName\lastrun" | Should -Exist
        }
        It "Should have the lastrun file date close to the current date/time" {
            $lastRun = Get-Date $(Get-Content "$installPath\$appName\lastrun" -Raw)
            $currentDate = Get-Date
            (New-TimeSpan -Start $lastRun -End $currentDate).Minutes | Should -BeLessThan 2
        }
    }
    Context "Banning" {
        It "Should log events for banned IPs with $testFAILEDLOGINTHRESHOLD login failures" {
            for($i=0;$i -le $testFAILEDLOGINTHRESHOLD;$i++) {
                CreateFAKESecurityEvent "$testBadIP1"
            }
            Sleep ([int]$testDELAY + 15)
            $currentDate=Get-Date 
            $expiryCutoffDate = $currentDate.AddMinutes(-$testLOCKOUTDURATION) 
            Get-WinEvent -FilterHashtable @{LogName="$appName";ID="100";StartTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") } | Should -Contain "$testBadIP1"
        }
        It "Should log events for banned IPs with more than $testFAILEDLOGINTHRESHOLD login failures" {
            for($i=0;$i -le ($testFAILEDLOGINTHRESHOLD+1);$i++) {
                CreateFAKESecurityEvent "$testBadIP2"
            }
            Sleep ([int]$testDELAY + 15)
            $currentDate=Get-Date 
            $expiryCutoffDate = $currentDate.AddMinutes(-$testLOCKOUTDURATION) 
            Get-WinEvent -FilterHashtable @{LogName="$appName";ID="100";StartTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") } | Should -Contain "$testBadIP2"
        }
        It "Should NOT ban IPs with less than $testFAILEDLOGINTHRESHOLD login failures" {
            CreateFAKESecurityEvent "$testBadIP3"
            Sleep ([int]$testDELAY + 15)
            $currentDate=Get-Date 
            $expiryCutoffDate = $currentDate.AddMinutes(-$testLOCKOUTDURATION) 
            Get-WinEvent -FilterHashtable @{LogName="$appName";ID="100";StartTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") } | Should -Not -Contain "$testBadIP3"
        }
        It "Should update the firewall rule with banned IPs with $testFAILEDLOGINTHRESHOLD login failures" {
            ((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq "$appName"}).remoteaddresses -split(',') | Should -Contain "$testBadIP1/255.255.255.255"
        }
        It "Should update the firewall rule with banned IPs with more than $testFAILEDLOGINTHRESHOLD login failures" {
            ((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq "$appName"}).remoteaddresses -split(',') | Should -Contain "$testBadIP2/255.255.255.255"
        }
        It "Should NOT BAN IPs that are whitelisted" {
            for($i=0;$i -le ($testFAILEDLOGINTHRESHOLD+1);$i++) {
                CreateFAKESecurityEvent "$testWhitelistedIP"
            }
            Sleep ([int]$testDELAY + 15)
            $currentDate=Get-Date 
            $expiryCutoffDate = $currentDate.AddMinutes(-$testLOCKOUTDURATION) 
            Get-WinEvent -FilterHashtable @{LogName="$appName";ID="100";StartTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") } | Should -Not -Contain "$testWhitelistedIP"
        }
    }
    Context "Unbanning" {
        It "Should log events for unbanning IPs after $testLOCKOUTDURATION minutes elapse" {
            # Wait for the ban to expire (with a little padding)
            Sleep ([int]$testLOCKOUTDURATION*75)
            Get-WinEvent -FilterHashtable @{LogName="$appName";ID="101"} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Unbanned ","") } | Should -Contain "$testBadIP1"
        }
        It "Should update the firewall rule with unbanned IPs after $testLOCKOUTDURATION minutes elapse" {
            ((New-Object -ComObject hnetcfg.fwpolicy2).rules | where {$_.name -eq "$appName"}).remoteaddresses -split(',') | Should -Not -Contain "$testBadIP1/255.255.255.255"
        }
    }
    Context "Innosetup Uninstaller" {
        It "Should run silently" {
            { Start-Process -Wait -WindowStyle Hidden -FilePath "$installPath\$appName\unins000.exe" -ArgumentList "/VERYSILENT" } | Should -Not -Throw
        }
        It "Should remove the windows event log" {
            { Get-WinEvent -ListLog "$appName" -ErrorAction Stop } | Should -Throw
        }
        It "Should remove the firewall rule" {
            $winFirewall = New-Object -ComObject hnetcfg.fwpolicy2
            ($winFirewall.rules | where {$_.name -eq "$appName" } | Measure-Object).Count | Should -Be 0
        }
        It "Should remove the scheduled task" {
            { Get-ScheduledTask -TaskName "$appName" -ErrorAction Stop } | Should -Throw
        }
        It "Should remove the folder under Program Files" {
            # This operation is intentionally delayed in the uninstaller and takes 15 seconds to complete
            Sleep 15
            "$installPath\$appName" | Should -Not -Exist
        }
    }
    AfterAll {
        # Delete the compiled installer from the desktop
        Remove-Item -Path "$env:USERPROFILE\Desktop\$installerName" -Force
        
        # Restore original (backup) files
        Copy-Item "$currentPath\EZWinBan.iss.bak" -Destination "$currentPath\EZWinBan.iss" -Force
        Copy-Item "$currentPath\process.ps1.bak" -Destination "$currentPath\process.ps1" -Force
        Copy-Item "$currentPath\config\settings.ini.bak" -Destination "$currentPath\config\settings.ini" -Force
        
        # Delete backup files
        Remove-Item -Path "$currentPath\*.bak" -Force
        Remove-Item -Path "$currentPath\config\*.bak" -Force
        
        # Remove fake event logs
        Remove-EventLog -LogName "FAKESecurity" -Confirm:$false
    }
}