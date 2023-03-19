. ".\Windows-Network-RelatedFunctions.ps1";
# ~ GLOBAL VARIABLES
$InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex);  # Get the interface index of the network adapter that is connected to the network
$ConnectionUrl = "https://www.howest.be"; # URL to test internet connectivity


# ~ CHECKS =======================================================================================================================================================================================================================================================
# CHECK OF SERVER IS CORE VERSION
function Show-IsServerCore
{
    $osServer = (Get-ComputerInfo | Select-Object OsServerLevel); # Get OS Server Level

    if($OsServer -eq "ServerCore") # Check if OS Server Level is ServerCore
    {
        return $true;
    }
    return $false;
}

# CHECK IF STATIC IP IS SET (DHCP IS Disabled = Static IP)
function Show-StaticIpSet
{
    $dhcpEnabled=(Get-NetIPInterface -InterfaceIndex $InterfaceIndex | Where-Object AddressFamily -eq "IPv4" | ForEach-Object {$_.Dhcp}); # Get DHCP status
    $StaticIpSet=(Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object AddressFamily -eq "IPv4" | ForEach-Object {$_.IPAddress}); # Get IP Address
    
    if($dhcpEnabled  -like "D*" -and $StaticIpSet) # Check if DHCP is disabled 
    {
        return $true;
    }
    return $false;
}

# CHECK DNS SERVER(s) IS SET
function Show-DnsServersSet
{
    $DnsServersSet=@(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceIndex); # Get DNS Servers

    if($null -ne ($DnsServersSet | ForEach-Object {$_.ServerAddresses})) # Check if DNS Servers ar not null
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
        Invoke-WebRequest -Uri $ConnectionUrl -UseBasicParsing -ErrorAction Stop | Out-Null;
        Write-Host "Internet access is available."
    }
    catch {
        Write-Host "Internet access is not available."
    }
}

# ~ ACTIONS ======================================================================================================================================================================================================================================================
# CHANGE COMPUTER NAME (with user input)
function Update-ComputerName
{
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$NewName
    );
  
    # Set the hostname (without restart option)
    Rename-Computer -NewName $NewName;
}

# SET IPv4 CONFIGURATION - IF ALREADY SET OVERWRITE SETTINGS (first clears previous settings) 
function Set-StaticIp
{
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [int]$InterfaceIndex,
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [bool]$OverWrite = $false,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$IpAddress,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [int]$Prefix,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$DefaultGateway
    );

    # Get user input
    if($DefaultGateway -eq (Get-BroadcastAddress -InterfaceIndex $InterfaceIndex)) # Check if default gateway is not the broadcast address
    {
        Write-Error "Default gateway can not be the broadcast address";
    }
    elseif($DefaultGateway -eq (Out-NetworkIpAddress -IpAddress $IpAddress -Prefix $Prefix)) # Check if default gateway is not the network address
    {
        Write-Error "Default gateway can not be the network address";
    }
    else
    {
        if($overWrite) # If overwrite is true clear previous settings
        {
            Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Remove-NetIPAddress -Confirm:$false; # Remove previous IP settings 
        }
        # Related commands inside transaction I one fails rollback - prevents loosing internet config
        Start-Transaction
        Get-NetIPInterface -InterfaceIndex $InterfaceIndex | Remove-NetRoute -Confirm:$false; # Remove previous default gateway
        if(!(Show-StaticIpSet)) { Set-NetIPInterface -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled; } # IF DHCP is enabled disable
        New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $IpAddress  -PrefixLength $Prefix -DefaultGateway $DefaultGateway -AddressFamily IPv4;
        Restart-NetAdapter -Name (Get-NetAdapter -InterfaceIndex $InterfaceIndex | Select-Object -ExpandProperty Name); # restart adapter
        Complete-Transaction;
    }
}

function Update-StaticIp
{
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [int]$InterfaceIndex,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$IpAddress,
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [int]$Prefix=0,
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetMask,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$DefaultGateway
    );

    if(0 -eq $Prefix)
    {
        $Prefix = (Get-NetworkPrefixLength -SubnetMask $SubnetMask);
        Write-Host "Prefix: $Prefix"
    }

    # Get user input
    # Check if static IP is already set, if so ask user if he wants to overwrite previous settings
    if(!(Show-StaticIpSet)) { Set-StaticIp -IpAddress $IpAddress -Prefix $Prefix -DefaultGateway $DefaultGateway; }
    else 
    { 
        Write-Host "Static configuration was alraedy set!";
        $overwriteConfig = Read-Host "Do you wish to overwrite the previous configuration?";
        if([string]$overwriteConfig.ToLower.Equals("y")) # If user wants to overwrite previous settings
        {
            Set-StaticIp -InterfaceIndex $InterfaceIndex `
            -IpAddress $IpAddress `
            -Prefix $Prefix `
            -DefaultGateway $DefaultGateway `
            -overWrite $true; # Set static IP with overwrite option
        }   
    }
    Write-Host "IP configuration succesfully set..."
}

function Set-DynamicIp
{
    param(
        [parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [int]$InterfaceIndex
    );
    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -Dhcp Enabled # EnableDHCP
    Write-Host "Enabled DHCP"
    if(Show-DnsServersSet) 
    {
        Write-Host "DNS server settings detected..."
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses # Clear DNS settings
        Write-Host "Removed previous DNS servers..." 
    } # Clear DNS settings
    Clear-DnsClientCache # Clear DNS cache
    Write-Host "DNS cash cleared..."
    if(Show-DefaultGatewaySet) # Check if default gateway is set, if so remove it
    { 
        Set-NetIPInterface -InterfaceIndex Ethernet0 | Remove-NetRoute -Confirm:$false 
        Write-Host "Removed prevous default gateway"
    } # Remove default gatewa
    Write-Host "The network interface will now be restarted to retrieve a new lease"
    Restart-NetAdapter -InterfaceIndex $InterfaceIndex # restart adapter to retrieve new lease
}

function Update-DNSServers
{
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [int]$InterfaceIndex,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$DnsServers
    );
    if(!(Show-DnsServersSet)) # Check if DNS servers are already set
    {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DnsServers; # Set DNS servers
        Write-Host "DNS servers succesfully set...";
    }
    else
    {
        Write-Host "DNS servers were already set!";
        $overwriteConfig = Read-Host "Do you wish to overwrite the previous configuration?";
        if([string]$overwriteConfig.ToLower.Equals("y")) # If user wants to overwrite previous settings
        {
            Clear-DnsClientCache # Clear DNS cache
            Write-Host "DNS cash cleared..."
            Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ($preferedDNS,$alternateDNS) # Set DNS servers
            Write-Host "Updated DNS servers..." 
        }
    }
}

function Disable-Ipv6
{
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    );
    Get-NetAdapterBinding -InterfaceIndex $InterfaceIndex | Set-NetAdapterBinding -Enabled:$false -ComponentID ms_tcpip6 # Disable IPv6 protocol for interface
    Write-Host "Disabled IPv6 protocol for interface $InterfaceIndex";
}

# ~ CHANGE TIMEZONE TO BRUSSELS 
function Update-TimeZoneToBrussels
{
    $desiredTimeZone = "Romance Standard Time" # Brussels timezone
    $currentTimeZone =  (Get-TimeZone).Id # Get current timezone
    # Check if current timezone is not Brussels
    if ($currentTimeZone -ne $desiredTimeZone) {
        Write-Host "Changing timezone to Brussels..."
        try { # Change timezone to Brussels 
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

function Enable-RemoteDesktop 
{
    Start-Transaction # Start transaction to undo changes if something goes wrong
        try 
        {
            # Enable RDP and allow RDP through firewall
            Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-Name "fDenyTSConnections" -Value 0 ;
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' -Name “UserAuthentication” -Value 1;
            Write-Host "Enabled Remote Desktop...";
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
            Write-Host "Allowed RDP trough firewall...";
            Complete-Transaction;
        }
        catch 
        {
            Write-Error "Could not enable RDP at this moment: $_";
            Undo-Transaction;
        }
}

# ~ UDPATE PREFERENCES ON DESKTOP EXPERIENCE 
function Update-Preferences
{
    if(!(Show-IsServerCore)) # Check if server is not core version - not applicable for core version
    {
        # Enable IE Enhanced Security for Administrators
        Write-Host "Disabling IE Enhanced Security for Administrators...";
        Start-Transaction # Start transaction to undo changes if something goes wrong
        try 
        {
            # Disable IE Enhanced Security for Administrators
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0;

            # Disable IE Enhanced Security for Users
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0;

            Write-Host "Disabled IE Enhanced Security for Everyone";

            Restart-NetAdapter -InterfaceAlias "*"; # Restart network adapter to apply changes
            Complete-Transaction;
        }
        catch 
        {
            Write-Error "Could not disable IE Enhanced Security for everyone: $_";
            Undo-Transaction;
        }

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

            # ENABLE CONTROL PANEL VIEW TO SMALL ICONS
            rite-Output "Setting Control Panel view to small icons...";
	        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
	        	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null;
	        }
	        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1;
	        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1;

            
        }
        catch
        {
            Write-Error "Error could not set preferences! restoring to previous settings: $_";
            Undo-Transaction
        }
    }
    else
    {
        Write-Host "Server Core detected, skipping settings preferences..."
    }
}

function Disable-IEEnhancedSecurity
{
    try {
        # Disable IE Enhanced Security for Administrators
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0;

        # Disable IE Enhanced Security for Users
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0;

        Write-Host "Disabled IE Enhanced Security for Everyone";

        Restart-NetAdapter -InterfaceAlias"*"; # Restart network adapter to apply changes
    }
    catch 
    {
        Write-Error "Could not disable IE Enhanced Security for everyone: $_";
    }
}
