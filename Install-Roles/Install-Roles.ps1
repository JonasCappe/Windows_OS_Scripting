. ./Network-RelatedFunctions.ps1 # Import the function to get the network part of an IP address
# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
$Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Admin -eq $False) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop; #variable contains information about the current invocation of the script, including the command used to start the script,
    exit;
}

# ~ global variables
$Roles = "AD-Domain-Services","DNS","DHCP"
$LogPath = "C:\Windows\NTDS"



# TO DO: Promotion of the server to a domain controller



# TO DO: Check if necessary roles are installed
foreach ($Role in $Roles) {
   
    
    if ((Get-WindowsFeature -Name $Role).Installed -eq $False) 
    {
        Install-WindowsFeature -Name $Role -IncludeManagementTools
    }
}

# TO DO: Create the first domain controller in the new forest and new windows domain
function InstallFirstDomainController
{
    $DomainName = Read-Host "Enter the domain name";
    $NetBiosName = Read-Host "Enter the NetBIOS name";
    $Answer = Read-Host "Change logging path (Y/N)?";
   if($Answer.ToLower -eq "Y")
    {
        $LogPath = Read-Host "Enter the new logging path";
    }

    Install-ADDSForest `
    -CreateDnsDelegation:$False `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "WinThreshold" `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBiosName `
    -ForestMode "WinThreshold" `
    -InstallDns:$True `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$False `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password") -AsPlainText -Force) `
    -Credential (Get-Credential) `
    -Force:$True;
}

# TO DO: reboot the server and wait for the server to come back online
Start-Sleep -Seconds 120;
Write-Host "Server has restarted proceding with script.";

# TO DO: After the reboot, check/correct the local DNS servers (Preferred and Alternate).
$DnsServers = Read-Host "Enter the DNS servers (comma seperated)";
$CurrentDnsServers = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex;

if($CurrentDnsServers.ServerAddresses -ne $DnsServers)
{
    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex -ServerAddresses ($DnsServers);
}

# TO DO: Create the reverse lookup zone for the subnet and make sure the pointer record of the first domain controller appears in that zone
$Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet0' -and $_.AddressFamily -eq 'IPv4' } # Get ipconfig of the first network adapter
$Subnet = Out-NetworkIpAddress -IpAddress $ipconfig.IPAddress -PrefixLength $ipconfig.PrefixLength; # Get the network part of the IP address

Add-DnsServerPrimaryZone -Name (Get-ReverseLookupZoneName -InterfaceAlias "Ethernet0" ) -NetworkID $Subnet -ReplicationScope "Domain" -DynamicUpdate "Secure";
Add-DnsServerResourceRecordPTR -Name $env:computername -PtrDomainName Get-ComputerFQDN -ZoneName ("" + (Get-ReverseLookupZoneName -InterfaceAlias "Ethernet0") +".")
# TO DO: Rename the 'default-first-site-name' to a meaningful name and add your subnet to it
$SiteName = Read-Host "Enter the site name";
Set-ADReplicationSite -Identity "Default-First-Site-Name" -Name $SiteName;
Add-ADReplicationSubnet -Site $SiteName -Name (Get-Subnet -InterfaceAlias "Ethernet0");


# TO DO: Authorize the DHCP server to serve DHCP requests in the subnet
Add-DhcpServerInDC

# TO DO: Remove warning about the DHCP server not being authorized to serve DHCP requests in the subnet
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableDhcpMediaSense" -Value 1 -Type DWord

# TO DO: Create IPv4 scope for the subnet (DHCP scope option)
Add-DhcpServerv4Scope -Name (Read-Host "Enter Scope name") -StartRange (Get-FirstAddressRange -InterfaceAlias "Etherner0") -EndRange (Get-LastAddressRange -InterfaceAlias "Etherner0")  -SubnetMask Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength; -State "Active"
# TO DO: Create the correct DHCP server options
Set-DhcpServerv4OptionValue -OptionId 6 -Value "10.0.0.1"
Set-DhcpServerv4OptionValue -OptionId 15 -Value "newdomain.com"
Set-DhcpServerv4OptionValue -OptionId 44 -Value "10.0.0.2"
Set-DhcpServerv4OptionValue


# ~ Functions ============================================================================================================
function Out-ReversedString # Function to reverse a string
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$string
    )

   <#
    1. Match each character in the string, right to left
    2. Get the value of each match
    3. Join the values together into a string
   #>
    return (([regex]::Matches($string,'.','RightToLeft') `
    | ForEach-Object {$_.value}) `
    -join '');
    
}
