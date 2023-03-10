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



# TO DO: Promotion of the server to a domain controller
function Add-Roles
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Roles
    );
    foreach ($Role in $Roles) 
    {
        if ((Get-WindowsFeature -Name $Role).Installed -eq $False) # Check if necessary roles are installed
        {
            Install-WindowsFeature -Name $Role -IncludeManagementTools
        }
    }
}
function Install-DomainController
{
    $DomainName = Read-Host "Enter the domain name";
    $NetBiosName = Read-Host "Enter the NetBIOS name";
    $Answer = Read-Host "Change logging path (Y/N)?";
   if($Answer.ToLower -eq "Y")
    {
        $LogPath = Read-Host "Enter the new logging path";
    }

    if(!(Show-FirstDomainController -Domain $DomainName))
    {
        Install-PrimaryDomainController -DomainName $DomainName -NetBiosName $NetBiosName -LogPath $LogPath;
    }
    else
    {
        # TO DO: Install Domain controller in Forest
        Write-Host "A domain controller already exists in the domain $DomainName";
    }
   
}
# Create the first domain controller in the new forest and new windows domain
# Modified from: NWB Script based on generated script wizard
function Install-PrimaryDomainController
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$NetBiosName,
        [parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath= "C:\Windows\NTDS"
    );

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

Install-SedondaryDomainController
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$NetBiosName,
        [parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath= "C:\Windows\NTDS"
    );
    Install-ADDSDomainController `
    -Credential (Get-Credential)
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBiosName `
    -InstallDns:$True `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$false `
    -NoGlobalCatalog:$false `
    -ReplicationSourceDC $ReplicationSourceDC `
    -SiteName $SiteName `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password") -AsPlainText -Force) `
    -Force:$true
}

# reboot the server and wait for the server to come back online
Start-Sleep -Seconds 120;
Write-Host "Server has restarted proceding with script.";

# After the reboot, check/correct the local DNS servers (Preferred and Alternate).
function Update-DNSServers
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$DnsServers
    );

    #$DnsServers = Read-Host "Enter the DNS servers (comma seperated)";
    $CurrentDnsServers = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex;

    if($CurrentDnsServers.ServerAddresses -ne $DnsServers)
    {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex -ServerAddresses ($DnsServers);
    }
}

function Add-ReversLookupZone
{
    # Create the reverse lookup zone for the subnet and make sure the pointer record of the first domain controller appears in that zone
    $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet0' -and $_.AddressFamily -eq 'IPv4' } # Get ipconfig of the first network adapter
    $Subnet = Out-NetworkIpAddress -IpAddress $ipconfig.IPAddress -PrefixLength $ipconfig.PrefixLength; # Get the network part of the IP address

    Add-DnsServerPrimaryZone -Name (Get-ReverseLookupZoneName -InterfaceAlias "Ethernet0" ) -NetworkID $Subnet -ReplicationScope "Domain" -DynamicUpdate "Secure";
    Add-DnsServerResourceRecordPTR -Name $env:computername -PtrDomainName Get-ComputerFQDN -ZoneName ("" + (Get-ReverseLookupZoneName -InterfaceAlias "Ethernet0") +".")
} # Source: https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverprimaryzone?view=windowsserver2022-ps



# Rename the 'default-first-site-name' to a meaningful name and add your subnet to it
function Update-DefaultFirstSiteName
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteName
    );
    # Rename the 'default-first-site-name' to a meaningful name and add your subnet to it
    #$SiteName = Read-Host "Enter the site name";
    Set-ADReplicationSite -Identity "Default-First-Site-Name" -Name $SiteName; # Rename the default site
    Add-ADReplicationSubnet -Site $SiteName -Name (Get-Subnet -InterfaceAlias "Ethernet0"); # Add the subnet of the first network adapter to the site
}

 function Enable-DHCCurrentSubnet
 {
    try 
    {
        Start-Transaction;
        $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet0' -and $_.AddressFamily -eq 'IPv4' }; # Get ipconfig of the first network adapter
        Add-DhcpServerInDC; # Authorize the DHCP server to serve DHCP requests in the subnet
        
        # Remove warning about the DHCP server not being authorized to serve DHCP requests in the subnet
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableDhcpMediaSense" -Value 1 -Type DWord;

        # Create IPv4 scope for the subnet (DHCP scope option)
        Add-DhcpServerv4Scope -Name (Read-Host "Enter Scope name") `
        -StartRange (Get-FirstAddressRange -InterfaceAlias "Ethernet0") `
        -EndRange (Get-LastAddressRange -InterfaceAlias "Ethernet0") `
        -SubnetMask Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength `
        -State "Active";
        Add-DhcpServer4ExcludeRange -ScopeId (Get-AddressInSubnet -InterfaceAlias "Ethernet0" -Place 0) -StartRange (Get-FirstAddressRange -InterfaceAlias "Ethernet0") -EndRange (Get-AddressInSubnet -InterfaceAlias "Ethernet0");
        Complete-Transaction;
    }
    catch 
    {
        Write-Error "Error could not Enable DHCP: $_";
        Undo-Transaction;
    }
 } # Source: https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverindc?view=windowsserver2022-ps




function Add-DHCPOptions # Add DHCP options
{

    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Options
    );
    if($Options.Count -eq 0)
    {
        Write-Error "No options were passed to the function";
        return;
    }

    for($i = 0; $i -lt $Options.Count; $i++)
    {
        if ($Option.ContainsKey({6,15,44}))
        {
            Write-Error "The options 6, 15 and 44 are required";
            return;
        }
        $Option = $Options[$i];
        Set-DhcpServerv4OptionValue -OptionId $Option.Key -Value $Option.Value;
    }
   
        
    Set-DhcpServerv4OptionValue -OptionId 6 -Value (Read-Host "Enter the DNS servers (comma seperated)");
    Set-DhcpServerv4OptionValue -OptionId 15 -Value (Read-Host "Enter the domain name");
}


# TO DO: 



# ~ Functions ============================================================================================================
function Out-ReversedString # Function to reverse a string
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$string
    );

   <#
    1. Match each character in the string, right to left
    2. Get the value of each match
    3. Join the values together into a string
   #>
    return (([regex]::Matches($string,'.','RightToLeft') `
    | ForEach-Object {$_.value}) `
    -join '');
    
}