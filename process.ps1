# ###############################
# EZWinBan
# https://github.com/neil-sabol/EZWinBan
# Neil Sabol
# neil.sabol@gmail.com
# ###############################

# Function to check whitelist.
# See https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/
function Check-Whitelist {
    # Read in subnet whitelist.
    $subnetWhitelist = get-content -path $PSSCriptRoot'\config\whitelist.txt' | Select -Skip 4
    foreach ($safesubnet in $subnetWhitelist) {
        [System.Net.IPAddress]$currentIP = $args[0]
        $subnetAndMask = $safesubnet.split("/")
        [System.Net.IPAddress]$currentSubnet = $subnetAndMask[0]
        [System.Net.IPAddress]$currentMask = $subnetAndMask[1]
        if($currentSubnet.Address -eq ($currentIP.Address -band $currentMask.Address)) {
            return $true
        }
    }
    return $false
}

#########################
# Initialization
#########################
# Ensure $PSSCriptRoot is set, even if PowerShell version is older - in this way, work directory
# and configuration is accessed relatively.
# See https://stackoverflow.com/questions/3667238/how-can-i-get-the-file-system-location-of-a-powershell-script
if (!$PSScriptRoot) {
    $PSSCriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

# Specify an application version
$appVer = "3.0"

# Setup the working path prefix directory
$workPath=$PSSCriptRoot

# Capture the PID of the PowerShell process currently running EZWinBan (needed for a clean uninstall).
$pid > "$workPath\pid"

# Log start event - Source: EZWinBan, EventID 10
Write-EventLog –LogName "EZWinBan" –Source "EZWinBan" –EntryType Information –EventID 10 –Message "EZWinBan $appVer started with PID $pid"

# Setup Windows Firewall object - used later to add new scope to an existing rule.
$winFirewall = New-Object -ComObject hnetcfg.fwpolicy2

# If this is the first run, set an initial run date to determine when to start the expiration process.
# Otherwise, read the last run date from the (persistent) file
if (Test-Path "$workPath\lastrun") {
    $lastRun = Get-Date $(Get-Content "$workPath\lastrun" -Raw)
} else {
    $lastRun = Get-Date
    $lastRun > "$workPath\lastrun"
}

# Get the Windows version (to handle non-standard source IP logging in Windows Server 2012
$osVersion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')

#########################
# Main Loop (Script)
#########################
while ($true) {
    # Re-read the current configuration from config\settings.ini each run (to capture changes)
    # See https://stackoverflow.com/questions/43690336/powershell-to-read-single-value-from-simple-ini-file
    $configSettings = Get-Content $PSSCriptRoot'\config\settings.ini' | Select -Skip 7 | ConvertFrom-StringData
    $lockoutDuration = $configSettings.LOCKOUTDURATION
    $failedLoginThreshold = $configSettings.FAILEDLOGINTHRESHOLD
    $logLookbackInterval = $configSettings.LOGLOOKBACKINTERVAL
    $executionDelay = $configSettings.DELAY
    $unBanInterval = $configSettings.UNBANINTERVAL

    # Setup date variables.
    $currentDate=Get-Date
    $expiryCutoffDate=$currentDate.AddMinutes(-$lockoutDuration)

    # Get the firewall rule named 'EZWinBan' (created by installer)
    $blockRule = $winFirewall.rules | where {$_.name -eq 'EZWinBan'}

    #########################
    # Execution
    #########################
    # Check for expired bans, remove them (if found), and rebuild the firewall rule with only the current banned IPs. 
    # Runs on the UNBANINTERVAL specified in settings.ini (minutes).
    if($((New-TimeSpan -Start $lastRun -End $currentDate).Minutes) -ge $unBanInterval) {
        [int]$expiredBanOffset = [int]$lockoutDuration + [int](New-TimeSpan -Start $lastRun -End $currentDate).Minutes
        $expiredBanBeginRange = $currentDate.AddMinutes(-$expiredBanOffset)
        $expiredIPs = Get-WinEvent -FilterHashtable @{LogName="EZWinBan";ID="100";StartTime=$expiredBanBeginRange;EndTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") }
        if(@($expiredIPs).Count -gt 0) {
            # Log expired (unbanned) IPs - Source: EZWinBan, EventID 101
            $expiredIPs | %{ Write-EventLog –LogName "EZWinBan" –Source "EZWinBan" –EntryType Information –EventID 101 –Message "Unbanned $_" }
    
            # Collect all remaining unique IPs that should remain blocked from the EZWinBan Event Log
            $allIPsToBlock=Get-WinEvent -FilterHashtable @{LogName="EZWinBan";ID="100";StartTime=$expiryCutoffDate} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data.Replace("Banned ","") } | Get-Unique
    
            # Rebuild the firewall rule scope with all current addresses (and a placeholder address 255.255.255.254/255.255.255.255).
            $blockRule.remoteaddresses='255.255.255.254/255.255.255.255';
            $allIPsToBlock | %{ $blockRule.remoteaddresses += ',' + $_ }
        }

        # Update the last expiry run date/time in the persistent file
        $lastRun = Get-Date
        $lastRun > "$workPath\lastrun"
    }

    # Select IP addresses from the Windows Security log that have audit failures (Event Code 4625) within the
    # "look back" date/time range.
    $failedLoginIPs=Get-WinEvent -FilterHashtable @{LogName="Security";ID="4625";StartTime=(Get-Date).AddMinutes(-$logLookbackInterval)} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data[19] } | select-object '#text'

    # Windows Server 2012 DOES NOT log source IPs in Event ID 4625 for RDP (even with NLA disabled) but it DOES log RDP
    # auth failures with EventCode 140 to Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.
    if($osVersion -like "*Windows Server 2012*" -and $osVersion -notlike "*Windows Server 2012 R2*" ) {
        # Select IP addresses from the Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational log that have login
        # failures (Event Code 140) within the "look back" date/time range and append them to the list
        $failedLoginIPs+=Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";ID="140";StartTime=(Get-Date).AddMinutes(-$logLookbackInterval)} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data } | select-object '#text'
    } 
        
    # Select IP addresses from the results that have $failedLoginThreshold or more bad logins.
    $failedLoginIPsOverThresh = $failedLoginIPs | group-object -property '#text' | where {$_.Count -ge $failedLoginThreshold} | Select -property Name

    # Split the existing IPs in the firewall rule into an array so we can search for existing IPs.
    $currentBannedIPs = $blockRule.RemoteAddresses -split(',')

    # Select IPs that are not whitelisted and not already in the firewall rule scope.
    $newIPsToBlock = $failedLoginIPsOverThresh | where {$_.Name.Length -gt 1 -and !(Check-Whitelist $_.Name) -and !($currentBannedIPs -contains $_.Name + '/255.255.255.255') }

    # If there are any new IPs to ban, add them to the firewall rule and log them
    if(@($newIPsToBlock).Count -gt 0) {
        # Add the new IPs that need to be blocked into the firewall rule.
        $newIPsToBlock | %{ $blockRule.remoteaddresses += ',' + $_.Name }

        # Log new banned IPs - Source: EZWinBan, EventID 100
        $bannedIPs = $newIPsToBlock.Name
        $bannedIPs | %{ Write-EventLog –LogName "EZWinBan" –Source "EZWinBan" –EntryType Information –EventID 100 –Message "Banned $_" }
    }

    # To regulate resource (CPU, Disk) usage - delay the next run for the period of time specified in settings.
    sleep $executionDelay
}