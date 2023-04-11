
Write-Host "Preparing remoting on the local machine...";
# Check if the WMI service is running
if ((Get-Service -Name "Winmgmt").Status -ne "Running") {
    # If the service is not running, start it and set it to start automatically
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

$TrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value; # Get the trusted hosts for remoting on the local machine
if(!($TrustedHosts -eq "192.168.1.*") -or $null -eq $TrustedHosts) # Check if the trusted hosts are set to the correct value
{
    Set-Item WSMan:\localhost\Client\TrustedHosts -Credential (Get-Credential -Message "Credential for local machine")  -Value "192.168.1.*" -Force; # Set the trusted hosts for remoting on the local machine
}

# ~ Environment variables =======================================================================================
# Remote devices to connect to
$PrimaryDomainController = "192.168.1.121"; # Set the primary domain controller
$SecondaryDomainController = "192.168.1.122"; # Set the secondary domain controller
$MemberServer = "192.168.1.120"; # Set the member server

# script paths
# Main script for installing the roles on a Windows Server
$SourcePath1 = "C:\Users\user\Desktop\Scripts\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, locally
$DestinationPath1 = "C:\temp\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, remotely

# Network related functions
$SourcePath2 = "C:\Users\user\Desktop\Scripts\Install-Roles.ps1";
$DestinationPath2 = "C:\temp\Install-Roles.ps1";

# Post-installation tasks
$SourcePath3 = "C:\Users\user\Desktop\Scripts\Post-InstallationFunctions_WindowsServer.ps1";
$DestinationPath3 = "C:\temp\Post-InstallationFunctions_WindowsServer.ps1";

# Remote path to the scripts
$RemotePath = "C:\temp\";

# Roles to install
$Roles = @("DNS", "DHCP", "AD-Domain-Services"); # Set the roles to install

#  Remote user
$RemoteUser = "administrator"; # Set the remote user

# Domain details
$Domain = "intranet.mct.be";
$SiteName = "INTRANET";

# IP addresses configuration
$NewSettings = @(
    @{
        Name = "win03-dc1";
        IPAddress = "192.168.1.2";
        SubnetMask = "255.255.255.0";
        DefaultGateway = "192.168.1.1";
    },
    @{
        Name = "win03-dc2";
        IPAddress = "192.168.1.3";
        SubnetMask = "255.255.255.0";
        DefaultGateway = "192.168.1.1";
    },
    @{
        Name = "win03-ms";
        IPAddress = "192.168.1.4";
        SubnetMask = "255.255.255.0";
        DefaultGateway = "192.168.1.1";
    }
);
$TempDNS = "$($NewSettings[0].DefaultGateway), $($NewSettings[0].IpAddress)"; # Set the temporary DNS server to the default gateway and the IP address of the first server 

# ~ PrimaryDomainController ==================================================================================================
$TargetSession = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server


# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList $RemotePath))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $RemotePath;
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath2 -Destination $DestinationPath2 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;




Invoke-Command -Session $TargetSession  -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";

    Update-ComputerName -NewName $using:NewSettings.Name; # Update the computer name

    # Retrieve the InterfaceIndex of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    Disable-Ipv6 -InterfaceIndex $InterfaceIndex; # Disable IPv6
    Update-DNSServers -InterfaceIndex $InterfaceIndex -DnsServers ($using:TempDNS); # Update the DNS servers
    Update-StaticIp -InterfaceIndex $InterfaceIndex -IpAddress $using:NewSettings[0].IpAddress -SubnetMask $using:NewSettings[0].SubnetMask -DefaultGateway $using:NewSettings[0].DefaultGateway; # Update the IP address, subnet mask
    Exit;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

$PrimaryDomainController = $NewSettings[0].IpAddress; # Set the primary domain controller to the new IP address
# Open a new session to the remote server
$TargetSession = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server

Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    # Then execute the scripts for loading the functions
    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles; # Add the roles defined in the $Roles variable

    Install-DomainController -DomainName $using:Domain -NetBiosName $using:SiteName; # Install the domain controller, check if primary domain controller exists for the provided domain name

    Write-Host "Restarting server..."
    Restart-Computer -Force;
    
}

# wait for the server to come back online - example microsoft docs didn't work, remote server was didn't respond
Start-Sleep -Seconds 600; # Wait for the server to restart by sleeping for 10 minutes
Write-Host "Server has restarted proceding with script...";


# Source: https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.3

#Remove-PSSession $TargetSession; # Remove the session to the remote server


# Create a new session to the remote server
$TargetSession = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser);
$DhcpOptions = @{
    6 = $PrimaryDomainController,$NewSettings[1].IpAddress;
    15 = $Domain
}

Invoke-Command -Session $TargetSession -ScriptBlock {
    
    Set-Location $using:RemotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Update-DNSServers -DnsServers "$($using:NewSettings[1].IpAddress)),$($using:PrimaryDomainController)";
    Add-ReversLookupZone;
    Update-DefaultFirstSiteName -SiteName $using:SiteName;
    Enable-DHCPCurrentSubnet;
    Add-DHCPOptions -Options $using:DhcpOptions;
    #Remove-Item -Path $RemotePath -Recurse -Force;
    Exit;

    # Source hashtables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.3
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

# ~ SecondaryDomainController ==================================================================================================
$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server

# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList $RemotePath))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $RemotePath;
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath2 -Destination $DestinationPath3 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;




Invoke-Command -Session $TargetSession  -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Windows-Network-RelatedFunctions.ps1";
    . ".\Post-InstallationFunctions_WindowsServer.ps1";

    Update-ComputerName -NewName $using:NewSettings[1].Name; # Update the computer name

    # Retrieve the InterfaceIndex of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    Disable-Ipv6 -InterfaceIndex $InterfaceIndex; # Disable IPv6
    Update-DNSServers -InterfaceIndex $InterfaceIndex -DnsServers "$($using:PrimaryDomainController),$($using:NewSettings[1].IpAddress)"; # Update the DNS servers
    Update-StaticIp -InterfaceIndex $InterfaceIndex -IpAddress $using:NewSettings[1].IpAddress -SubnetMask $using:NewSettings[1].SubnetMask -DefaultGateway $using:NewSettings[1].DefaultGateway; # Update the IP address, subnet mask
    exit;
}


Remove-PSSession $TargetSession; # Remove the session to the remote server
$SecondaryDomainController = $NewSettings[1].IpAddress; # Set the secondary domain controller to the new IP address
$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser);

Invoke-Command -Session $TargetSession -ScriptBlock { Restart-Computer -Force };

# wait for the server to come back online - example microsoft docs didn't work, remote server was didn't respond
Start-Sleep -Seconds 600; # Wait for the server to restart by sleeping for 10 minutes
Write-Host "Server has restarted proceding with script...";

$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";
    
    Update-Preferences;
    Write-Host "Joining domain...";
    Add-Computer -DomainName $using:Domain -Credential (Get-Credential -Message "Domain join" -Username "$($using:SiteName)\$($using:RemoteUser)"); # Add the computer to the domain
    Write-Host "Joining domain complete";
    Write-Host "Cleaning up scripts..."
    #Remove-Item -Path $using:RemotePath -Recurse -Force;
    Write-Host "Cleaning up scripts complete";
    Write-Host "Restarting server...";
    Restart-Computer -Force;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

# ~ MemberServer ==================================================================================================
#Enable-PSRemoting -Force
#Enable-NetFirewallRule -DisplayName "*Network Access*"
#Enable-NetFirewallRule -DisplayGroup "*Remote Event Log*"
#Enable-NetFirewallRule -DisplayGroup "*Remote File Server Resource Manager Management*"

#Enable-NetFirewallRule -DisplayGroup "Netlogon Service"
$TargetSession = New-PSSession -ComputerName $MemberServer -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server

# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath2 -Destination $DestinationPath3 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;


Invoke-Command -Session $TargetSession  -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";

    Update-ComputerName -NewName $using:NewSettings[2].Name; # Update the computer name

    # Retrieve the InterfaceIndex of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    Disable-Ipv6 -InterfaceIndex $InterfaceIndex; # Disable IPv6
    Update-DNSServers -InterfaceIndex $InterfaceIndex -DnsServers "$($using:PrimaryDomainController),$($using:NewSettings[1].IpAddress)"; # Update the DNS servers
    Update-StaticIp -InterfaceIndex $InterfaceIndex -IpAddress $using:NewSettings[2].IpAddress -SubnetMask $using:NewSettings[2].SubnetMask -DefaultGateway $using:NewSettings[2].DefaultGateway; # Update the IP address, subnet mask
    exit;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

$MemberServer = $NewSettings[2].IpAddress; # Set the member server to the new IP address
$TargetSession = New-PSSession -ComputerName $MemberServer -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server

    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";
    
    Update-Preferences;
    Write-Host "Joining domain...";
    Add-Computer -DomainName $using:Domain -Credential (Get-Credential -Message "Domain join" -Username "$($using:SiteName)\$($using:RemoteUser)"); # Add the computer to the domain
    Write-Host "Joining domain complete";
    Write-Host "Cleaning up scripts..."
    Remove-Item -Path using:$RemotePath -Recurse -Force;
    Write-Host "Cleaning up scripts complete";
    Write-Host "Restarting server...";
    Restart-Computer -Force;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

# ~ SecondaryDomainController - Setup ==================================================================================================
$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath2 -Destination $DestinationPath2 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;


Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    # Then execute the scripts for loading the functions
    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles; # Add the roles defined in the $Roles variable
    Install-DomainController -DomainName $using:Domain -NetBiosName $using:SiteName; # Install the domain controller, check if primary domain controller exists for the provided domain name

    Write-Host "Restarting server..."
    Restart-Computer -Force;
    exit;
}
$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
Invoke-Command -Session $TargetSession -ScriptBlock {
    Set-Location $using:RemotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    Enable-DHCPCurrentSubnet;
    
    Remove-Item -Path $using:RemotePath -Recurse -Force;
    exit;

    # Source hashtables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.3
}
Remove-PSSession $TargetSession; # Remove the session to the remote server

$TargetSessionDhcp = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username "$($SiteName)\$($RemoteUser)"); # Create a new session to the remote server

Invoke-Command -Session $TargetSessionDhcp -ScriptBlock {
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    
    $Ipconfig = (Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }); # Get ipconfig of the first network adapter

    Set-Location $using:RemotePath

    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";

    $FailoverScope = (Get-DhcpServerv4Failover -ScopeId "$(Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -PrefixLength $Ipconfig.PrefixLength)" -ErrorAction SilentlyContinue);
    if($FailoverScope)
    {
        # Update DHCP replication
        Set-DhcpServerv4Failover -InputObject $FailoverScope `
        -PartnerServer $using:SecondaryDomainController `
        -Name "DHCP-FAILOVER" `
        -LoadBalancePercent 60 `
        -SharedSecret (ConvertTo-SecureString (Read-Host "Sharedsecret" -AsSecureString) -AsPlainText -Force);
    }
    else
    {
        # Configure DHCP replication
        Add-DhcpServerv4Failover -ScopeId "$(Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -PrefixLength $Ipconfig.PrefixLength)" `
        -PartnerServer $using:SecondaryDomainController `
        -Name "DHCP-FAILOVER" `
        -LoadBalancePercent 60 `
        -SharedSecret (ConvertTo-SecureString (Read-Host "Sharedsecret" -AsSecureString) -AsPlainText -Force);
    }

    # Get the existing DNS record for the domain name
    $ExistingRecord = (Get-DnsServerResourceRecord -ZoneName $using:Domain -RRType A -Name "dns*" -ErrorAction SilentlyContinue);
    if($ExistingRecord)
    {
        $ExistingRecord | Remove-DnsServerResourceRecord;
    }
    
    # Create a new DNS record with the weighted IP addresses
    #Add-DnsServerResourceRecord -ZoneName $using:Domain -Name "dns1" -CName -HostNameAlias "$($using:NewSettings[0].Name).$($using:Domain)" -priority 0 -Weight 50;
    #Add-DnsServerResourceRecord -ZoneName $using:Domain -Name "dns2" -CName -HostNameAlias "$($using:NewSettings[1].Name).$($using:Domain)" -priority 0 -Weight 50;
    
    

    # Restart the DHCP and DNS servers
    Restart-Service -Name dhcpserver, dns -Force
}

Remove-PSSession $TargetSessionDhcp; # Remove the session to the remote server


