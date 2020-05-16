# This is based entirely on Nathan Studebaker's work (https://blog.watchpointdata.com/author/nathan-studebaker)
# See: https://blog.watchpointdata.com/rdp-brute-force-attack-detection-and-blacklisting-with-powershell
# This project simply automates the setup/installation of the script, adds the ability to whitelist addresses/networks,
# and provides a separate ini file to configure basic options. Snippets pulled from others work as well (cited inline).
# Neil Sabol (neil.sabol@gmail.com)

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
If (!$PSScriptRoot) {
    $PSSCriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

# Setup the working path prefix directory
$workPath=$PSSCriptRoot+'\work'

# Capture the PID of the PowerShell process currently running EZWinBan (needed for a clean uninstall).
$pid > "$workPath\pid"

# Setup Windows Firewall object - used later to add new scope to an existing rule.
$winFirewall = New-Object -ComObject hnetcfg.fwpolicy2

# Set an initial run date to determine when to start the expiration process.
$lastRun = Get-Date

#########################
# Main Loop (Script)
#########################
while ($true) {

    # Read the current configuration from config\settings.ini
    # See https://stackoverflow.com/questions/43690336/powershell-to-read-single-value-from-simple-ini-file
    $configSettings = Get-Content $PSSCriptRoot'\config\settings.ini' | Select -Skip 7 | ConvertFrom-StringData
    $lockoutDuration = $configSettings.LOCKOUTDURATION
    $failedLoginThreshold = $configSettings.FAILEDLOGINTHRESHOLD
    $logLookbackInterval = $configSettings.LOGLOOKBACKINTERVAL
    $loggingEnabled = $configSettings.LOGGING
    $executionDelay = $configSettings.DELAY

    # Setup date variables.
    $currentDate=[DateTime]::Now
    $expiryCutoffDate=$currentDate.AddHours(-$lockoutDuration)

    # Setup working path and file variables - the path is "work" and log files are named based.
    # on the current date
    $currentWorkFileName=$currentDate.ToString('yyyyMMddHH')+'.log'

    # Get the firewall rule named 'EZWinBan' (created by installer)
    $blockRule = $winFirewall.rules | where {$_.name -eq 'EZWinBan'}

    #########################
    # Execution
    #########################

    # Check for expired work files, remove them (if found), and rebuild the firewall rule with only the current blocks. 
    # Runs every 15 minutes.
    if($((New-TimeSpan -Start $lastRun -End $(Get-Date)).Minutes) -ge 15) {
        $expiredBlocks=Get-ChildItem $workPath | Where-Object { $_.Name -like '*.log' } | Where-Object { $_.CreationTime -lt $expiryCutoffDate }
        if($expiredBlocks) {
            # Log expired (unbanned) IPs - Source: EZWinBan, EventID 101
            if ($loggingEnabled -eq "yes") {
    	        $expiredIPs = $expiredBlocks | %{ get-content $workPath\$_ }
                if (@($expiredIPs).Count -gt 0) {
                    Write-EventLog –LogName Application –Source "EZWinBan" –EntryType Information –EventID 101 –Message "Expired (unbanned) IPs = $($expiredIPs.count): $($expiredIPs -join ',')"
                }
            }

            # Delete files containing blocked IPs that are past the cutoff.
            $expiredBlocks | Remove-Item -Force
    
            # Collect all remaining unique IPs to block from the work files - since expired work files were deleted, the
            # resulting IPs will be within the lockout duration specified in configuration.
            $allIPsToBlock=get-content -path $workPath'\*.log' | Get-Unique
    
            # Rebuild the firewall rule scope with all current addresses (and a placeholder address 255.255.255.254/255.255.255.255).
            $blockRule.remoteaddresses='255.255.255.254/255.255.255.255';
            $allIPsToBlock | %{ $blockRule.remoteaddresses += ',' + $_ }
        }

        # Update the lastRunMinute
        $lastRun = Get-Date
    }

    # Select IP addresses from the Windows Security log that have audit failures (Event Code 4625) within the "look back" date/time range.
    $failedLoginIPs=Get-WinEvent -FilterHashtable @{LogName="Security";ID="4625";StartTime=(Get-Date).AddMinutes(-$logLookbackInterval)} -ErrorAction SilentlyContinue | ForEach { ([xml]$_.ToXml()).Event.EventData.Data[19] } | select-object '#text'

    # Select IP addresses from the results that have $failedLoginThreshold or more bad logins.
    $failedLoginIPsOverThresh = $failedLoginIPs | group-object -property '#text' | where {$_.Count -ge $failedLoginThreshold} | Select -property Name

    # Split the existing IPs in the firewall rule into an array so we can search for existing IPs.
    $currentBannedIPs = $blockRule.RemoteAddresses -split(',')

    # Select IPs that are not whitelisted and not already in the firewall rule scope.
    $newIPsToBlock = $failedLoginIPsOverThresh | where {$_.Name.Length -gt 1 -and !(Check-Whitelist $_.Name) -and !($currentBannedIPs -contains $_.Name + '/255.255.255.255') }

    # Write the new IPs that need to be blocked into today's work file.
    $newIPsToBlock.Name >> "$workPath\$currentWorkFileName"

    # Add the new IPs that need to be blocked into the firewall rule.
    $newIPsToBlock | %{ $blockRule.remoteaddresses += ',' + $_.Name }

    # Log new banned IPs - Source: EZWinBan, EventID 100
    if ($loggingEnabled -eq "yes") {
        $bannedIPs = $newIPsToBlock.Name
        if ($bannedIPs -gt 0) {
            Write-EventLog –LogName Application –Source "EZWinBan" –EntryType Information –EventID 100 –Message "New banned IPs = $($bannedIPs.count): $($bannedIPs -join ',')"
        }
    }

    # To regulate resource (CPU) usage - delay the next run for the period of time specified in settings.
    sleep $executionDelay
}