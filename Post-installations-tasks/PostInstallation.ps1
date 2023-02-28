# EVERYTHING IN THIS SCRIPT IS WRITTEN BASED ON PREVIOUS SCRIPTS WRITTEN BY ME AND LOOS POWERSHELL COMMANDS FROM MY SYSTEM DOCUMENTATION FROM NWB AND TI


# TODO: REFACTOR CODE: SPLITS THINS MORE IN THERE OWN SCOPES SRP!
# TODO: TEMP BACKUP REGISTRY BEFORE CHANGING IT
# TODO: ADD TRANSACTIONS => TO MAKE ROLLBACK POSSIBLE ON FAILURE



# ~ GLOBAL VARIABLES
$interfaceAlias = "Ethernet0";
$connectionUrl = "https://www.howest.be"

# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($admin -eq $false) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop; #variable contains information about the current invocation of the script, including the command used to start the script,
    exit;
}
# ~ CHECKS =======================================================================================================================================================================================================================================================
# CHECK OF SERVER IS CORE VERSION
function Show-IsServerCore
{
    $osServer = (Get-ComputerInfo | Select-Object OsServerLevel)

    if($OsServer -eq "ServerCore")
    {
        return $true;
    }
    return $false;
}

# CHECK IF STATIC IP IS SET (DHCP IS Disabled = Static IP)
function Show-StaticIpSet
{
    $dhcpEnabled=(Get-NetIPInterface -ifAlias $interfaceAlias | Where-Object AddressFamily -eq "IPv4" | ForEach-Object {$_.Dhcp});
    if($dhcpEnabled  -like "D*")
    {
        return $true;
    }
    return $false;
}

# CHECK DNS SERVER(s) IS SET
function Show-DnsServersSet
{
    $dnsServersSet=@(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias $interfaceAlias);

    if($null -ne ($dnsServersSet | ForEach-Object {$_.ServerAddresses}))
    {
        return $true;
    }
    return $false;   
}

# CHECK IF DEFAULT GATEWAY HAS BEEN SET BY LOOKING AT THE ROUTING TABLE
function Show-DefaultGatewaySet
{
    if($null -eq (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Where-Object {$_.RouteMetric -ne 0})) # Check Default Gateway settings
    {
        return $true;
    }
    return $false;
}

# CHECK IF INTERNET IS REACHABLE (connectivity + nameresolution)
function Show-InternetIsReachable
{
    try {
        Invoke-WebRequest -Uri $connectionUrl -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Host "Internet access is available."
    }
    catch {
        Write-Host "Internet access is not available."
    }
}

# ~ ACTIONS ======================================================================================================================================================================================================================================================
# CHANGE COMPUTER NAME (with user input)
function Update-ComputerNamne
{
    Clear-Host
    $newName = Read-Host "Enter new computer name";

    # Set the hostname (without restart option)
    Rename-Computer -NewName $newName;
}

# SET IPv4 CONFIGURATION - IF ALREADY SET OVERWRITE SETTINGS (first clears previous settings)
function Set-StaticIp
{
    param([bool]$overWrite = $false)

    $ipAddress = Read-Host "Enter the IP address"
    $prefix = Read-Host "Enter the network prefix"
    $defaultGateway = Read-Host "Enter the default gateway"

    if($overWrite) # On existing first clear config
    {
        Get-NetIPAddress -InterfaceAlias $interfaceAlias | Remove-NetIPAddress  -Confirm:$false # Remove previous IP settings 
    }
    # Related commands inside transaction I one fails rollback - prevents loosing internet config
    Start-Transaction
    Get-NetIPInterface -InterfaceAlias $interfaceAlias | Remove-NetRoute -Confirm:$false # Remove previous default gateway
    if(!(Show-StaticIpSet)) { Set-NetIPInterface -InterfaceAlias $interfaceAlias -AddressFamily IPv4 -Dhcp Disabled } # IF DHCP is enabled disable
    New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $ipAddress  -PrefixLength $prefix -DefaultGateway $defaultGateway -AddressFamily IPv4
    Restart-NetAdapter -InterfaceAlias $InterfaceAlias # restart adapter
    Complete-Transaction 

}

# ~ CHANGE TIMEZONE TO BRUSSELS
function Update-TimeZoneToBrussels
{
    $desiredTimeZone = "Romance Standard Time"
    $currentTimeZone =  (Get-TimeZone).Id
    
    if ($currentTimeZone -ne $desiredTimeZone) {
        Write-Host "Changing timezone to Brussels..."
        try {
            Set-TimeZone -Id $desiredTimeZone -ErrorAction Stop
            Write-Host "Timezone changed to Brussels."
        }
        catch {
            Write-Error "Error changing timezone to Brussels: $_"
        }
    }
    else {
        Write-Host "Timezone is already set to Brussels."
    }
}

# ~ UDPATE PREFERENCES ON DESKTOP EXPERIENCE
function Update-Preferences
{
    if(!(Show-IsServerCore))
    {
        Write-Host "Desktop Experience detected Settings preferences..."
        Start-Transaction
        try
        {
            # Display FILE EXTENSIONS
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "HideFileExt" -Value 0

            Write-Host "Enabled File extensions..."

            # Display HIDDEN FILES
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "Hidden" -Value 1

            Write-Host "Enabled show hidden files..."

            # ENABLE NUMLOCK ON BOOT
            Set-ItemProperty -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Value 2
            Write-Host "Enabled numlock on boot..."

            # SET KEYBOARD TO QWERTY (en-US)
            Set-WinUserLanguageList -LanguageList en-US -Force
            Write-Host "Updated keyboard to Qwerty(US)..."
        }
        catch
        {
            Write-Error "Error could not set preferences! restoring to previous settings: $_";
            Undo-Transaction
        }
        Complete-Transaction
    }
}

# ~ MENUS =========================================================================================================================================================================================================================================================
# ~ CHANGE NETWORK CONFIG
function Show-NetworkConfigMenu 
{
    Clear-Host
    Write-Host "========== Network Configuration =========="
    Write-Host "0. Set Dynamic IP Address"
    Write-Host "1. Set Static IP Address"
    Write-Host "2. Set DNS Servers"
    Write-Host "3. Disable IPv6"
    Write-Host "4. Check Internet Connection"
    Write-Host "5. Return to Main Menu"

    $choice = Read-Host "Please make a selection"
    switch ($choice) 
    {
        '0'
        { 
            Set-NetIPInterface -InterfaceAlias $interfaceAlias -Dhcp Enabled # EnableDHCP
            Write-Host "Enabled DHCP"
            if(Show-DnsServersSet) 
            {
                Write-Host "DNS server settings detected..."
                Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ResetServerAddresses
                Write-Host "Removed previous DNS servers..." 
            } # Clear DNS settings
            Clear-DnsClientCache # Clear DNS cache
            Write-Host "DNS cash cleared..."
            if(Show-DefaultGatewaySet) 
            { 
                Set-NetIPInterface -InterfaceAlias Ethernet0 | Remove-NetRoute -Confirm:$false 
                Write-Host "Removed prevous default gateway"
            } # Remove default gateway

            Write-Host "The network interface will now be restarted to retrieve a new lease"
            Restart-NetAdapter -InterfaceAlias $InterfaceAlias # restart adapter
            
        }
        '1' 
        { 
            if(!(Show-StaticIpSet)) { Set-StaticIp }
            else 
            { 
                Write-Host "Static configuration was alraedy set!"
                $overwriteConfig = Read-Host "Do you wish to overwrite the previous configuration?"
                if([string]$overwriteConfig.ToLower.Equals("y"))
                {
                    Set-StaticIp -overWrite $true
                }   
            }
            Write-Host "IP configuration succesfully set..."
        }
        '2' 
        { 
            $preferedDNS = Read-Host "Enter prefered DNS server: "
            $alternateDNS = Read-Host "Enter Alternate DNS server: "
            Clear-DnsClientCache
            Write-Host "DNS cash cleared..."
            Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses ($preferedDNS,$alternateDNS) 
            Write-Host "Updated DNS servers..." 
        }
        '3'
        {
            Get-NetAdapterBinding -InterfaceAlias $interfaceAlias | Set-NetAdapterBinding -Enabled:$false -ComponentID ms_tcpip6
            Write-Host "Disabled IPv6 protocol for interface $InterfaceAlias";
        }
        '4' { Show-InternetIsReachable }
        '5' { return }
        default { Display-NetworkConfigMenu }
    }
    pause
    Show-NetworkConfigMenu
}

# ~ ENABLE REMOTE DESKTOP
function Show-RemoteDesktopMenu 
{
    Clear-Host
    Write-Host "========== Remote Desktop =========="
    Write-Host "1. Enable Remote Desktop"
    Write-Host "2. Allow Non-Admins to Remote In"
    Write-Host "3. Return to Main Menu"

    $choice = Read-Host "Please make a selection: "
    switch ($choice) 
    {
        '1' 
        { 
            Start-Transaction
            try {
                Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-Name "fDenyTSConnections" -Value 0 
                Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' -Name “UserAuthentication” -Value 1 
                Write-Host "Enabled Remote Desktop..."
                Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
                Write-Host "Allowed RDP trough firewall..."
            }
            catch {
                Write-Error "Could not enable RDP at this moment: $_"
                Undo-Transaction
            }
            Complete-Transaction
            
        }
        '2' 
        { 
            $user = Read-Host "Enter User of user to allow to remote in: "
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $user 
        }
        '3' { return }
        default { Display-RemoteSettingsMenu }
    }
    pause
    Show-RemoteSettingsMenu
}

# ~ DISABLE IE ENHANCED SECURITY (on Desktop experience)
function Show-IEEnhancedSecurityMenu
{
    if(!(Show-IsServerCore))
    {
        Clear-Host
        Write-Host "========== Remote Settings =========="
        Write-Host "1. Disable for Admins"
        Write-Host "2. Disable for Users"
        Write-Host "3. Disable for everyone"
        $choice = Read-Host "Please make a selection: "
    
        switch ($choice) 
        {
            '1' 
            {
                try {
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
                    Write-Host "Disabled IE Enhanced Security for Administrators"
                }
                catch {
                    Write-Error "Could not disable IE Enhanced Security for administrators: $_"
                } 
                 
            }
            '2' 
            { 
                try {
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
                    Write-Host "Disabled IE Enhanced Security for Users"
                }
                catch {
                    Write-Error "Could not disable IE Enhanced Security for users: $_"
                }
                 
            }
            '3' 
            {
                try {
                    # DISABLE FOR ADMINS
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
    
                    # DISABLE FOR USER
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0

                    Write-Host "Disabled IE Enhanced Security for Everyone"
                }
                catch {
                    Write-Error "Could not disable IE Enhanced Security for everyone: $_"
                }
                
            }
            '4' { return }
            default { Show-IEEnhancedSecurityMenu }
        }
        pause
        Show-IEEnhancedSecurityMenu
    }
    else 
    {
        Write-Host "IE Enhanced Security is not pressent on Core servers. Ignoring request."
        return
    }
}
