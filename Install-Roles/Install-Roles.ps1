. ./Network-RelatedFunctions.ps1 # Import the function to get the network part of an IP address
# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($admin -eq $false) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop; #variable contains information about the current invocation of the script, including the command used to start the script,
    exit;
}

# ~ global variables
$roles = "AD-Domain-Services","DNS","DHCP"
$logPath = "C:\Windows\NTDS"



# TO DO: Promotion of the server to a domain controller



# TO DO: Check if necessary roles are installed
foreach ($role in $roles) {
   
    
    if ((Get-WindowsFeature -Name $role).Installed -eq $false) 
    {
        Install-WindowsFeature -Name $role -IncludeManagementTools
    }
}

# TO DO: Create the first domain controller in the new forest and new windows domain
$domainName = Read-Host "Enter the domain name";
$netBiosName = Read-Host "Enter the NetBIOS name";
$answer = Read-Host "Change logging path (Y/N)?";
if($answer.ToLower -eq "Y")
{
    $logPath = Read-Host "Enter the new logging path";
}

Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName $domainName `
-DomainNetbiosName $netBiosName `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath $logPath `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword (ConvertTo-SecureString (Read-Host "Recovery password") -AsPlainText -Force) `
-Credential (Get-Credential) `
-Force:$true;
# TO DO: reboot the server and wait for the server to come back online
Start-Sleep -Seconds 120;
Write-Host "Server has restarted proceding with script.";

# TO DO: After the reboot, check/correct the local DNS servers (Preferred and Alternate).
$dnsServers = Read-Host "Enter the DNS servers (comma seperated)";
$currentDnsServers = Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex;

if($currentDnsServers.ServerAddresses -ne $dnsServers)
{
    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*"}).InterfaceIndex -ServerAddresses ($dnsServers);
}

# TO DO: Create the reverse lookup zone for the subnet and make sure the pointer record of the first domain controller appears in that zone
$ipconfig = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq 'Ethernet0' -and $_.AddressFamily -eq 'IPv4' } # Get ipconfig of the first network adapter
$subnet = Out-NetworkIpAddress -IpAddress $ipconfig.IPAddress -PrefixLength $ipconfig.PrefixLength; # Get the network part of the IP address

Add-DnsServerPrimaryZone -Name (Get-ReverseLookupZoneName -InterfaceAlias "Ethernet0" ) -NetworkID $subnet -ReplicationScope "Domain"
Add-DnsServerResourceRecordPTR -Name "DC1" -PTRDomainName $subnet.Split('/')[0] -ZoneName "10.0.0.x.in-addr.arpa"
# TO DO: Rename the 'default-first-site-name' to a meaningful name and add your subnet to it

# TO DO: Configure as DHCP server - Check if nessary roles are installed
# TO DO: Authorize the DHCP server to serve DHCP requests in the subnet

# TO DO: Remover warning about the DHCP server not being authorized to serve DHCP requests in the subnet

# TO DO: Create IPv4 scope for the subnet (DHCP scope option)

# TO DO: Create the correct DHCP server options



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
