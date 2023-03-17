<#
    .SYNOPSIS 
    Script to install the necessary roles and promote the server to a domain controller

    .Description
    This script installs the necessary roles and promotes the server to a domain controller, including the DNS and DHCP roles

    .COMPONENT
    Windows Server
    
    .FUNCTIONALITY
    INSTALLATION, SERVER, DOMAIN CONTROLLER, DNS, DHCP, ROLES
#>
# https://learn.microsoft.com/en-us/powershell/scripting/developer/help/examples-of-comment-based-help?view=powershell-7.3

# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
<#$Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Admin -eq $False) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop; #variable contains information about the current invocation of the script, including the command used to start the script,
    exit;
}#>
#Set-Location .\Install-Roles # Set the current directory to the directory of the script
#Set-Location .\Install-Roles # Set the current directory to the directory of the script

. ".\Windows-Network-RelatedFunctions.ps1" # Import the function to get the network part of an IP address

$InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network


#$ADController = (Read-Host "Enter the name of the AD controller").ToLower();

function Add-Roles
{
    <#
        .SYNOPSIS
        install the necessary roles

        .DESCRIPTION
        installs the necessary roles if they are not already installed

        .PARAMETER Roles
        The roles to install

        .EXAMPLE
        Add-Roles -Roles @("DNS","DHCP")
    #>
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Roles
    );
    foreach ($Role in $Roles) 
    {
        if ((Get-WindowsFeature -Name $Role).Installed -eq $False) # Check if necessary roles are installed
        {
            Write-host "Installing $Role..."   
            Install-WindowsFeature -Credential (Get-Credential) -Name $Role -IncludeManagementTools
            Write-Host "$Role installed"
        }
        else
        {
            Write-Host "$Role already installed"
        }
    }
}
# Promotion of the server to a domain controller
function Install-DomainController
{   
    <#
        .SYNOPSIS
        promote the server to a domain controller

        .DESCRIPTION
        This function promotes the server to a domain controller

        .NOTES
        Check if the server is already promoted to a domain controller, 
        if not, check if a domain controller already exists in the domain, 
        if not, create the first domain controller in the new forest and new windows domain, 
        if yes, create a domain controller in the existing forest and domain

        .EXAMPLE
        Install-DomainController
    #>
    if(!(Show-PromotionInProgress)) # Check if the server is already promoted to a domain controller
    {
        # Ask for the domain name, the NetBIOS name and the logging path
        $LogPath = "C:\Windows\NTDS"; # Default logging path
        $DomainName = Read-Host "Enter the domain name";
        $NetBiosName = (Read-Host "Enter the NetBIOS name").ToUpper();
        # prompt the user to change the logging path
        $Answer = Read-Host "Change logging path (Y/N)?";
        if($Answer.ToLower -eq "Y") # Check if the logging path should be changed, if so, ask for the new path
        {
            $LogPath = Read-Host "Enter the new logging path";
        }
    

        if($null -eq (Get-PrimaryDC)) # Check if a domain controller already exists in the domain
        {
            Write-Host "No domain controller exists in the domain $DomainName"
            Install-PrimaryDomainController -DomainName $DomainName -NetBiosName $NetBiosName -LogPath $LogPath;
        }
        else
        {
            # TO DO: Install Domain controller in Forest
            Write-Host "A domain controller already exists in the domain $DomainName";
            Install-SecondaryDomainController -DomainName $DomainName -NetBiosName $NetBiosName -LogPath $LogPath;
        }
    }
    else
    {
        Write-Host "The server is already promoted to a domain controller";
    }
    
   
}
# Create the first domain controller in the new forest and new windows domain
# Modified from: NWB Script based on generated script wizard
function Install-PrimaryDomainController
{
    <#
        .SYNOPSIS
        Create the first domain controller in the new forest and new windows domain

        .DESCRIPTION
        creates the first domain controller in the new forest and new windows domain

        .PARAMETER DomainName
        The name of the domain

        .PARAMETER NetBiosName
        The NetBIOS name of the domain

        .PARAMETER LogPath
        The path where the logs should be stored

        .EXAMPLE
        Install-PrimaryDomainController -DomainName "contoso.com" -NetBiosName "CONTOSO" [-LogPath "C:\Windows\NTDS"]
    #>
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
    -DatabasePath $LogPath `
    -DomainMode "WinThreshold" `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBiosName `
    -ForestMode "WinThreshold" `
    -InstallDns:$True `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$True `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password" -AsSecureString) -AsPlainText -Force) `
    -Force:$True;
}

function Install-SecondaryDomainController
{
    <#
        .SYNOPSIS
        Create a domain controller in the existing forest and domain

        .DESCRIPTION
        creates a domain controller in the existing forest and domain

        .PARAMETER DomainName
        The name of the domain

        .PARAMETER NetBiosName
        The NetBIOS name of the domain

        .PARAMETER LogPath
        The path where the logs should be stored

        .EXAMPLE
        Install-SecondaryDomainController -DomainName "contoso.com" -NetBiosName "CONTOSO" [-LogPath "C:\Windows\NTDS"]
    #>
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
    -DatabasePath $LogPath `
    -DomainMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBiosName `
    -InstallDns:$True `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$True `
    -NoGlobalCatalog:$false `
    -ReplicationSourceDC $ReplicationSourceDC `
    -SiteName $SiteName `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password"-AsSecureString) -AsPlainText -Force) `
    -Force:$true
}


# After the reboot, check/correct the local DNS servers (Preferred and Alternate).
function Update-DNSServers
{
    <#
        .SYNOPSIS
        Update the DNS servers

        .DESCRIPTION
        Updates the DNS servers

        .PARAMETER DnsServers
        The DNS servers (comma seperated)

        .EXAMPLE
        Update-DNSServers -DnsServers "1.1.1.3,1.0.0.3"
    #>
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$DnsServers
    );
    
    # Get the current DNS servers
    $CurrentDnsServers = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex;

    # Check if the DNS servers are correct, if not, update them
    if($CurrentDnsServers.ServerAddresses -ne $DnsServers)
    {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ($DnsServers);
    }
}

function Add-ReversLookupZone
{
    <#
        .SYNOPSIS
        Add the reverse lookup zone

        .DESCRIPTION
        Adds the reverse lookup zone for the subnet and makes sure the pointer record of the first domain controller appears in that zone

        .EXAMPLE
        Add-ReversLookupZone
    #>
    # Get the interface index of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    # Create the reverse lookup zone for the subnet and make sure the pointer record of the first domain controller appears in that zone
    $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' } # Get ipconfig of the first network adapter
    
    $Subnet = Out-NetworkIpAddress -IpAddress $Ipconfig.IpAddress -PrefixLength ($Ipconfig.PrefixLength); # Get the network part of the IP address
   
    Add-DnsServerPrimaryZone -NetworkID $Subnet -ReplicationScope "Domain" -DynamicUpdate "Secure";
    Add-DnsServerResourceRecordPTR -Name $env:computername -PtrDomainName Get-ComputerFQDN -ZoneName ("0." + (Get-ReverseLookupZoneName -InterfaceIndex $InterfaceIndex));
} # Source: https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverprimaryzone?view=windowsserver2022-ps



# Rename the 'default-first-site-name' to a meaningful name and add your subnet to it
function Update-DefaultFirstSiteName
{
    <#
        .SYNOPSIS
        Rename the 'default-first-site-name' to a meaningful name and add your subnet to it

        .DESCRIPTION
        Renames the 'default-first-site-name' to a meaningful name and add your subnet to it

        .PARAMETER SiteName
        The name of the site

        .EXAMPLE
        Update-DefaultFirstSiteName -SiteName "intranet"
    #>
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteName
    );
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network

    # Rename the 'default-first-site-name' to a meaningful name and add your subnet to it

    # Rename the 'default-first-site-name' to a meaningful name
    Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'objectclass -like "site"' | Set-ADObject -DisplayName $SiteName; 
    Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'objectclass -like "site"' | Rename-ADObject -NewName $SiteName;

    New-ADReplicationSubnet -Site $SiteName -Name (Get-Subnet -InterfaceIndex $InterfaceIndex); # Add the subnet of the first network adapter to the site
}

 function Enable-DHCCurrentSubnet
 {
    try 
    {
        Start-Transaction;
        $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq '$InterfaceIndex' -and $_.AddressFamily -eq 'IPv4' }; # Get ipconfig of the first network adapter
        Add-DhcpServerInDC; # Authorize the DHCP server to serve DHCP requests in the subnet
        
        # Remove warning about the DHCP server not being authorized to serve DHCP requests in the subnet
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableDhcpMediaSense" -Value 1 -Type DWord;

        # Create IPv4 scope for the subnet (DHCP scope option)
        Add-DhcpServerv4Scope -Name (Read-Host "Enter Scope name") `
        -StartRange (Get-FirstAddressRange -InterfaceIndex "$InterfaceIndex") `
        -EndRange (Get-LastAddressRange -InterfaceIndex "$InterfaceIndex") `
        -SubnetMask Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength `
        -State "Active";
        Add-DhcpServer4ExcludeRange -ScopeId (Get-AddressInSubnet -InterfaceIndex $InterfaceIndex -Place 0) -StartRange (Get-FirstAddressRange -InterfaceIndex $InterfaceIndex) -EndRange (Get-AddressInSubnet -InterfaceIndex "$InterfaceIndex");
        Set-DhcpServerv4OptionValue -ScopeId (Get-AddressInSubnet -InterfaceIndex $InterfaceIndex -Place 0) -Router (Get-LastAddressRange -InterfaceIndex $InterfaceIndex);
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
    <#
        .SYNOPSIS
        Add DHCP options

        .DESCRIPTION
        Adds DHCP options

        .PARAMETER Options
        The DHCP options

        .EXAMPLE
        Add-DHCPOptions -Options @{option1="value1";option2="value2"}
    #>

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
            Write-Error "The options 6, 15 required";
            return;
        }
        $Option = $Options[$i];
        Set-DhcpServerv4OptionValue -OptionId $Option.Key -Value $Option.Value;
    }
}
# ~ Functions ============================================================================================================
function Out-ReversedString # Function to reverse a string
{
    <#
        .SYNOPSIS
        Function to reverse a string

        .DESCRIPTION
        Function to reverse a string

        .PARAMETER String
        The string to reverse

        .EXAMPLE
        Out-ReversedString -String "string"
    #>
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
# ========================================================================================================================

