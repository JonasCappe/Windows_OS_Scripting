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
        Write-Output "Internet access is available."
    }
    catch {
        Write-Output "Internet access is not available."
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
    Get-NetIPInterface -InterfaceAlias $interfaceAlias | Remove-NetRoute -Confirm:$false # Remove previous default gateway
    if(!(Show-StaticIpSet)) { Set-NetIPInterface -InterfaceAlias $interfaceAlias -AddressFamily IPv4 -Dhcp Disabled } # IF DHCP is enabled disable
    New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $ipAddress  -PrefixLength $prefix -DefaultGateway $defaultGateway -AddressFamily IPv4
    Restart-NetAdapter -InterfaceAlias $InterfaceAlias # restart adapter 

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
            if(Show-DnsServersSet) { Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ResetServerAddresses } # Clear DNS settings
            Clear-DnsClientCache # Clear DNS cache
            if(Show-DefaultGatewaySet) { Set-NetIPInterface -InterfaceAlias Ethernet0 | Remove-NetRoute -Confirm:$false } # Remove default gateway
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
        }
        '2' 
        { 
            $preferedDNS = Read-Host "Enter prefered DNS server: "
            $alternateDNS = Read-Host "Enter Alternate DNS server: "
            Clear-DnsClientCache
            Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses ($preferedDNS,$alternateDNS) 
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