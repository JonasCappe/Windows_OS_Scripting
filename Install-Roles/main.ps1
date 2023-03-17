<#
    .SYNOPSIS
    This script installs the roles on a Windows Server remotely

    .DESCRIPTION
    This script installs the roles on a Windows Server remotely

    .Example
    .\main.ps1
#>
# ~ Environment variables =======================================================================================
$ComputerName = (Read-Host "Enter the name of the AD controller"); # Set the computer name
$targetSession = New-PSSession -ComputerName $ComputerName -Credential (Get-Credential); # Create a new session to the remote server
# Main script for installing the roles on a Windows Server
$SourcePath1 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, locally
$DestinationPath1 = "C:\temp\Windows-Network-RelatedFunctions.ps1"; # Path to the script containing the functions, remotely

# Network related functions
$SourcePath2 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Install-Roles.ps1";
$DestinationPath2 = "C:\temp\Install-Roles.ps1";

$Roles = @("DNS", "DHCP", "AD-Domain-Services"); # Set the roles to install


# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $targetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $targetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

#. ".\Install-Roles.ps1";
#. ".\Windows-Network-RelatedFunctions.ps1";
# Copy the scripts to the remote server
Copy-Item -ToSession $targetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $targetSession -Path $SourcePath2 -Destination $DestinationPath2 -Force;

$remotePath = "C:\temp\" # Set the remote path


Invoke-Command -Session $targetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:remotePath; # First set the working directory to the remote path
    # Then execute the scripts for loading the functions
    . ".\Install-Roles.ps1"; 
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles; # Add the roles defined in the $Roles variable
    Install-DomainController; # Install the domain controller, check if primary domain controller exists for the provided domain name

    Write-Host "Restarting server..."
    Restart-Computer -Force;
}
# Source: https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.3

Remove-PSSession $targetSession; # Remove the session to the remote server

# wait for the server to come back online - example microsoft docs didn't work, remote server was didn't respond
Start-Sleep -Seconds 600; # Wait for the server to restart by sleeping for 10 minutes
Write-Host "Server has restarted proceding with script...";

# Create a new session to the remote server
$targetSession = New-PSSession -ComputerName $ComputerName -Credential (Get-Credential);
Invoke-Command -Session $targetSession -ScriptBlock {
    Set-Location $using:remotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    Update-DNSServers -DnsServers (Read-Host "Enter the DNS servers (comma seperated)");
    Add-ReversLookupZone;
    Update-DefaultFirstSiteName -SiteName (Read-Host "Enter new default-first-sitename");
    Enable-DHCCurrentSubnet;
    Add-DHCPOptions -Options @{6=(Read-Host "Enter the DNS servers (comma seperated)"); 15=(Read-Host "Enter the domain name")};

    # Source hashtables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.3
}