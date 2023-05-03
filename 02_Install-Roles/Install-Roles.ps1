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
    if(!(Show-PromotionInProgress)) # Check if the server is already promoted to a domain controller
    {
        # Ask for the domain name, the NetBIOS name and the logging path
        $LogPath = "C:\Windows\NTDS"; # Default logging path
        #$DomainName = Read-Host "Enter the domain name";
        #$NetBiosName = (Read-Host "Enter the NetBIOS name").ToUpper();
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
    -DomainName $DomainName `
    -SiteName $NetBiosName `
    -InstallDns:$True `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$True `
    -NoGlobalCatalog:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password"-AsSecureString) -AsPlainText -Force) `
    -Credential (Get-Credential -Message "Credentials Domain Admin" -Username "$($NetBiosName)\administrator") `
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
    #$Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }; # Get ipconfig of the first network adapter
    
    $Subnet = Get-Subnet -InterfaceIndex $InterfaceIndex; # Get the network part of the IP address

    if(-not (Get-DnsServerZone -ZoneName (Get-ReverseLookupZoneName -InterfaceIndex $InterfaceIndex) -ErrorAction SilentlyContinue))
    {
        Add-DnsServerPrimaryZone -NetworkID $Subnet -ReplicationScope "Domain" -DynamicUpdate "Secure";
    }
    
    if(-not (Get-DnsServerResourceRecord -Name $env:computername -ZoneName (Get-ReverseLookupZoneName -InterfaceIndex $InterfaceIndex) -RRType "Ptr" -ErrorAction SilentlyContinue))
    {
        Add-DnsServerResourceRecordPTR -Name $env:computername -PtrDomainName Get-ComputerFQDN -ZoneName (Get-ReverseLookupZoneName -InterfaceIndex $InterfaceIndex);
    }
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
    # Check if the current site name is already the provided site name
    $CurrentSiteName = (Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'objectclass -like "site"').DisplayName
    if ($CurrentSiteName -ne $SiteName) {
        # Rename the 'default-first-site-name' to a meaningful name
        Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'objectclass -like "site"' | Set-ADObject -DisplayName $SiteName; 
        Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'objectclass -like "site"' | Rename-ADObject -NewName $SiteName;
    }

    if(-not (Get-ADReplicationSubnet -Identity (Get-Subnet -InterfaceIndex $InterfaceIndex) -ErrorAction SilentlyContinue))
    {
        New-ADReplicationSubnet -Site $SiteName -Name (Get-Subnet -InterfaceIndex $InterfaceIndex); # Add the subnet of the first network adapter to the site
    }
    
}

 function Enable-DHCPCurrentSubnet # TO DO Single Responsibility Principle => This function should only enable DHCP on the current subnet
 {
    try 
    {
        $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' } # Get ipconfig of the first network adapter
    
        Start-Transaction;
        $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
        $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' }; # Get ipconfig of the first network adapter
        $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength; # Get the subnet mask of the first network adapter
        $Subnet = Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -SubnetMask (Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength);

        if ((Get-DhcpServerInDc| Where-Object { $_.IPAddress -eq $Ipconfig.IPAddress })) # Check if the DHCP server is already authorized to serve DHCP requests in the subnet
        {
            Write-Warning "DHCP server is already authorized for the subnet."
        } 
        else 
        {
            Add-DhcpServerInDC; # Authorize the DHCP server to serve DHCP requests in the subnet
            Write-Host "DHCP server authorized for the subnet."
        }
        
        # Remove warning about the DHCP server not being authorized to serve DHCP requests in the subnet
        # function Disable-DhcpWarningFlag
        Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2;
        # Function to create a DHCP scope for the current subnet
        if (Get-DhcpServerv4Scope | Where-Object { $_.Name -eq "intranet" -and $_.StartRange -eq "192.168.1.1" -and $_.EndRange -eq "192.168.1.254" -and $_.SubnetMask -eq "255.255.255.0" } -ErrorAction SilentlyContinue)
        {
            Write-Warning "DHCP scope already exists for the subnet."
        } 
        else {

            # Create IPv4 scope for the subnet (DHCP scope option)
            Add-DhcpServerv4Scope -Name (Read-Host "Enter Scope name") `
            -StartRange (Get-FirstAddressRange -InterfaceIndex "$InterfaceIndex") `
            -EndRange (Get-LastAddressRange -InterfaceIndex "$InterfaceIndex") `
            -SubnetMask (Convert-PrefixToSubnetMask -PrefixLength $Ipconfig.PrefixLength) `
            -State "Active";
            Write-Host "DHCP scope created for the subnet."
        }

        # Function to create a DHCP reservation for the current subnet
      

        if($null -ne (Get-DhcpServerv4ExclusionRange -ScopeId $Subnet))
        {
            Write-Warning "DHCP exclusion range already exists for the subnet.";
        }
        else
        {
            # Create IPv4 exclusion range for the subnet (DHCP scope option) - 1st 12 addresses
            Add-DhcpServerv4ExclusionRange -ScopeId (Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -SubnetMask $SubnetMask) -StartRange (Get-FirstAddressRange -InterfaceIndex $InterfaceIndex) -EndRange (Get-AddressInSubnet -InterfaceIndex "$InterfaceIndex" -Place 12);
            #Add-DhcpServerv4ExclusionRange -ScopeId (Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -SubnetMask $SubnetMask) -StartRange (Get-LastAddressRange -InterfaceIndex $InterfaceIndex) -EndRange (Get-LastAddressRange -InterfaceIndex $InterfaceIndex);
            Write-Host "DHCP exclusion range created for the subnet.";
        }
        
        if($null -ne (Get-DhcpServerv4OptionValue -ScopeId $Subnet -OptionId 3 -ErrorAction SilentlyContinue))
        {
            Write-Warning "DHCP option 3 already exists for the subnet.";
        }
        else 
        {
            Set-DhcpServerv4OptionValue -ScopeId (Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -SubnetMask $SubnetMask) -Router (Get-FirstAddressRange -InterfaceIndex $InterfaceIndex);
            Write-Host "DHCP option 3 created for the subnet.";
        }
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
        Add-DHCPOptions -Options @{6 = "203.113.11.1","203.113.11.2"; 15 = "intranet.mct.be" }
}
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

    if (15 -notin $Options.Keys -or 6 -notin $Options.Keys) {
        Write-Error "The options 6, 15 are required";
    }
    else 
    {
        foreach ($option in $Options.GetEnumerator()) 
        {
            if(Get-DhcpServerv4OptionValue -OptionId $option.Key -ErrorAction SilentlyContinue)
            {
                Write-Warning "DHCP option $option.Key already exists.";
            }
            else 
            {
                Set-DhcpServerv4OptionValue -OptionId $option.Key -Value $option.Value -ErrorAction SilentlyContinue -Force;
                Write-Host "DHCP option $option.Key created.";
            }
        }
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

