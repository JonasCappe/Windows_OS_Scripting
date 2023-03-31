
Write-Host "Preparing remoting on the local machine...";
$TrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value; # Get the trusted hosts for remoting on the local machine
if(!($TrustedHosts -eq "203.113.11.*") -or $null -eq $TrustedHosts) # Check if the trusted hosts are set to the correct value
{
    Set-Item WSMan:\localhost\Client\TrustedHosts -Credential (Get-Credential -Message "Credential for local machine")  -Value "203.113.11.*" -Force; # Set the trusted hosts for remoting on the local machine
}

# ~ Environment variables =======================================================================================
# Remote devices to connect to
$PrimaryDomainController = "203.113.11.1"; # Set the primary domain controller
$SecondaryDomainController = "203.113.11.2"; # Set the secondary domain controller
$MemberServer = "203.113.11.3"; # Set the member server

# script paths
# Main script for installing the roles on a Windows Server
$SourcePath1 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, locally
$DestinationPath1 = "C:\temp\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, remotely

# Network related functions
$SourcePath2 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Install-Roles.ps1";
$DestinationPath2 = "C:\temp\Install-Roles.ps1";

# Post-installation tasks
$SourcePath3 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Post-InstallationFunctions_WindowsServer.ps1";
$DestinationPath3 = "C:\temp\Post-InstallationFunctions_WindowsServer.ps1";

# Remote path to the scripts
$RemotePath = "C:\temp\";

# Roles to install
$Roles = @("DNS", "DHCP", "AD-Domain-Services"); # Set the roles to install

#  Remote user
$RemoteUser = "administrator"; # Set the remote user

# ~ PrimaryDomainController ==================================================================================================
$TargetSession = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server


# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $TargetSession -Path $SourcePath2 -Destination $DestinationPath2 -Force;


Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    # Then execute the scripts for loading the functions
    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles; # Add the roles defined in the $Roles variable
    Install-DomainController; # Install the domain controller, check if primary domain controller exists for the provided domain name

    Write-Host "Restarting server..."
    Restart-Computer -Force;
    Exit-PSSession;
}
# Source: https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.3

#Remove-PSSession $TargetSession; # Remove the session to the remote server

# wait for the server to come back online - example microsoft docs didn't work, remote server was didn't respond
Start-Sleep -Seconds 600; # Wait for the server to restart by sleeping for 10 minutes
Write-Host "Server has restarted proceding with script...";

# Create a new session to the remote server
#$TargetSession = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser);
$DhcpOptions = @{
    6 = "203.113.11.1","203.113.11.2";
    15 = "intranet.mct.be"
}

Invoke-Command -Session $TargetSession -ScriptBlock {
    Set-Location $using:RemotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    Update-DNSServers -DnsServers (Read-Host "Enter the DNS servers (comma seperated)");
    Add-ReversLookupZone;
    Update-DefaultFirstSiteName -SiteName (Read-Host "Enter new default-first-sitename");
    Enable-DHCPCurrentSubnet;
    Add-DHCPOptions -Options $using:DhcpOptions;
    Remove-Item -Path $RemotePath -Recurse -Force;
    Exit-PSSession

    # Source hashtables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.3
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

# ~ SecondaryDomainController ==================================================================================================
$TargetSession = New-PSSession -ComputerName $SecondaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server

# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;

$NewName = Read-Host "Enter the new computer name";
$IPAddress = Read-Host "Enter the IP address";
$SubnetMask = Read-Host "Enter the subnet mask";
$DefaultGateway = Read-Host "Enter the gateway";


Invoke-Command -Session $TargetSession  -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";

    Update-ComputerName -NewName $using:NewName; # Update the computer name

    # Retrieve the InterfaceIndex of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    Disable-Ipv6 -InterfaceIndex $InterfaceIndex; # Disable IPv6
    Update-DNSServers -InterfaceIndex $InterfaceIndex -DnsServers (Read-Host "Enter the DNS servers (comma seperated)"); # Update the DNS servers
    Update-StaticIp -InterfaceIndex $InterfaceIndex -IpAddress $using:IPAddress -SubnetMask $using:SubnetMask -DefaultGateway $using:DefaultGateway; # Update the IP address, subnet mask
    Exit-PSSession;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

$TargetSession = New-PSSession -ComputerName $IPAddress -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";
    
    Update-Preferences;
    Write-Host "Joining domain...";
    Add-Computer -DomainName (Read-Host "Enter domain to join") -Credential (Get-Credential -Message "Domain join" -Username $using:RemoteUser); # Add the computer to the domain
    Write-Host "Joining domain complete";
    Write-Host "Cleaning up scripts..."
    Remove-Item -Path using:$RemotePath -Recurse -Force;
    Write-Host "Cleaning up scripts complete";
    Write-Host "Restarting server...";
    Restart-Computer -Force & Exit-PSSession;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

# ~ MemberServer ==================================================================================================
$TargetSession = New-PSSession -ComputerName $MemberServer -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser);; # Create a new session to the remote server

# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the scripts to the remote server
Copy-Item -ToSession $TargetSession -Path $SourcePath3 -Destination $DestinationPath3 -Force;

$NewName = Read-Host "Enter the new computer name";
$IPAddress = Read-Host "Enter the IP address";
$SubnetMask = Read-Host "Enter the subnet mask";
$DefaultGateway = Read-Host "Enter the gateway";


Invoke-Command -Session $TargetSession  -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";

    Update-ComputerName -NewName $using:NewName; # Update the computer name

    # Retrieve the InterfaceIndex of the network adapter that is connected to the network
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    Disable-Ipv6 -InterfaceIndex $InterfaceIndex; # Disable IPv6
    Update-DNSServers -InterfaceIndex $InterfaceIndex -DnsServers (Read-Host "Enter the DNS servers (comma seperated)"); # Update the DNS servers
    Update-StaticIp -InterfaceIndex $InterfaceIndex -IpAddress $using:IPAddress -SubnetMask $using:SubnetMask -DefaultGateway $using:DefaultGateway; # Update the IP address, subnet mask
    Exit-PSSession;
}

Remove-PSSession $TargetSession; # Remove the session to the remote server

$TargetSession = New-PSSession -ComputerName $IPAddress -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server
Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    Write-Host $using:RemotePath;
    
    # Then execute the scripts for loading the functions
    . ".\Post-InstallationFunctions_WindowsServer.ps1";
    
    Update-Preferences;
    Write-Host "Joining domain...";
    Add-Computer -DomainName (Read-Host "Enter domain to join") -Credential (Get-Credential -Message "Domain join" -Username $using:RemoteUser); # Add the computer to the domain
    Write-Host "Joining domain complete";
    Write-Host "Cleaning up scripts..."
    Remove-Item -Path using:$RemotePath -Recurse -Force;
    Write-Host "Cleaning up scripts complete";
    Write-Host "Restarting server...";
    Restart-Computer -Force & Exit-PSSession;
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


Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:RemotePath; # First set the working directory to the remote path
    # Then execute the scripts for loading the functions
    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles; # Add the roles defined in the $Roles variable
    Install-DomainController; # Install the domain controller, check if primary domain controller exists for the provided domain name

    Write-Host "Restarting server..."
    Restart-Computer -Force;
    Exit-PSSession;
}
Invoke-Command -Session $TargetSession -ScriptBlock {
    Set-Location $using:RemotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    Update-DNSServers -DnsServers (Read-Host "Enter the DNS servers (comma seperated)");

    Enable-DHCPCurrentSubnet;
    
    Remove-Item -Path $RemotePath -Recurse -Force;
    Exit-PSSession

    # Source hashtables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.3
}
Remove-PSSession $TargetSession; # Remove the session to the remote server
$TargetSessionDhcp = New-PSSession -ComputerName $PrimaryDomainController -Credential (Get-Credential -Message "Credentials remote machine" -Username $RemoteUser); # Create a new session to the remote server

Invoke-Command -Session $TargetSessionDhcp -ScriptBlock {
    $InterfaceIndex = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike 'Microsoft*' -and $_.InterfaceAlias -notlike '*Virtual*'} | Select-Object -ExpandProperty InterfaceIndex); # Get the interface index of the network adapter that is connected to the network
    
    $Ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }; # Get ipconfig of the first network adapter

    # Configure DHCP replication
    Add-DhcpServerv4Failover -ScopeId (Out-NetworkIpAddress -IpAddress $Ipconfig.IPAddress -PrefixLength $Ipconfig.PrefixLength) `
    -PartnerServer $using:SecondaryDomainController `
    -Name "DHCP-FAILOVER" `
    -LoadBalancePercentage 60 `
    -SharedSecret (ConvertTo-SecureString (Read-Host "Sharedsecret" -AsSecureString) -AsPlainText -Force);

    # Set DNS server load balancing
    Add-DnsServerZoneDelegation -Name "intranet.mct.be" `
    -NameServer "$using:PrimaryDomainController,$using:SecondaryDomainController" `
    -IPAddress "$using:PrimaryDomainController,$using:SecondaryDomainController" `
    -LoadBalancePercent 60 `
    -PassThru | Set-DnsServerZoneDelegation -NameServer "$using:PrimaryDomainController,$using:SecondaryDomainController";

    # Restart the DHCP and DNS servers
    Restart-Service -Name dhcpserver, dns -Force
}

Remove-PSSession $TargetSessionDhcp; # Remove the session to the remote server

# TO DO: make the above code more abstract, and create dynamic functions
