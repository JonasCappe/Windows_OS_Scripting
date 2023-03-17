$ComputerName = (Read-Host "Enter the name of the AD controller");
$targetSession = New-PSSession -ComputerName $ComputerName -Credential (Get-Credential);
$SourcePath1 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Windows-Network-RelatedFunctions.ps1";
$DestinationPath1 = "C:\temp\Windows-Network-RelatedFunctions.ps1";
$SourcePath2 = "D:\Powershell\Windows_OS_Scripting\Install-Roles\Install-Roles.ps1";
$DestinationPath2 = "C:\temp\Install-Roles.ps1";

$Roles = @("DNS", "DHCP", "AD-Domain-Services");
$InterfaceAlias = "Ethernet0";

# Check if the destination folder exists, and create it if it doesn't
if (-not (Invoke-Command -Session $targetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $targetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

#. ".\Install-Roles.ps1";
#. ".\Windows-Network-RelatedFunctions.ps1";
Copy-Item -ToSession $targetSession -Path $SourcePath1 -Destination $DestinationPath1 -Force;
Copy-Item -ToSession $targetSession -Path $SourcePath2 -Destination $DestinationPath2 -Force;

$remotePath = "C:\temp\"

Write-Host $Roles;
Invoke-Command -Session $targetSession -ArgumentList $Roles -ScriptBlock {
    Set-Location $using:remotePath
    . ".\Install-Roles.ps1";
    . ".\Windows-Network-RelatedFunctions.ps1";
    
    Add-Roles -Roles $using:Roles;
    Install-DomainController;
}



# reboot the server and wait for the server to come back online
Write-Host "Restarting server..."
Restart-Computer -ComputerName $ComputerName -Wait -For PowerShell -Timeout 300 -Delay 2; 
# Source: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restart-computer?view=powershell-7.3#example-6-restart-a-remote-computer-and-wait-for-powershell
Write-Host "Server has restarted proceding with script...";




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





