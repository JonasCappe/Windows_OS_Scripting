

# ~ GLOBAL VARIABLES ====================================================================================================

$Infrastructure = @(
    @{
        Name = "win13-DC1"
        IpAddress = "192.168.1.2"
    }
    @{
        Name = "win13-DC2"
        IpAddress = "192.168.1.3"
    }
    @{
        Name = "win13-MS"
        IpAddress = "192.168.1.4"
    }
); # Remote machines
$UPN = "mct.be" # UPN suffix
$RemotePath = "C:\temp"; # Remote path

Write-Host "Preparing remoting on the local machine...";
# Check if the WMI service is running
if ((Get-Service -Name "Winmgmt").Status -ne "Running") {
    # If the service is not running, start it and set it to start automatically
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

$TrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value; # Get the trusted hosts for remoting on the local machine
if(!($TrustedHosts -eq "192.168.1.4") -or $null -eq $TrustedHosts) # Check if the trusted hosts are set to the correct value
{
    Set-Item WSMan:\localhost\Client\TrustedHosts -Credential (Get-Credential -Message "Credential for local machine" -UserName "intranet\administrator") -Value "192.168.1.4" -Force; # Set the trusted hosts for remoting on the local machine
}

# ~ Add UPN suffix ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].IpAddress -Credential (Get-Credential -Message "Enter credentials for $($Infrastructure[0].Name)" -UserName "intranet\Administrator");



Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Create UPN suffix
    Get-ADForest | Set-ADForest -UPNSuffixes @{add="$using:UPN"}; # Add UPN suffix to Active Directory
    # Source: https://shellgeek.com/add-upn-suffix-in-active-directory/#Add_UPN_Suffix_in_Active_Directory_using_PowerShell
}

# ~ Create Shares ==================================================================================================
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process;
Set-Location "C:\Users\user\Desktop\Scripts\03_Windows_Active_Directory_Objects\";
. ".\Object_Functions.ps1";

Add-Shares -SourceFile ".\SharesDc2.csv" -DestinationServer $Infrastructure[1].IpAddress; # Add shares to DC2
Add-Shares -SourceFile ".\SharesFileServer.csv" -DestinationServer $Infrastructure[2].IpAddress; # Add shares to FileServer

# ~ Organizatinal Units & Groups ======================================================================================================================
# Copy script & CSV's to Primary Domain Controller (DC1), for remote execution
Copy-Item -ToSession $PrimaryDomainControllerSession -Path ".\*" -Destination $RemotePath; # Copy script to Primary Domain Controller

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Object_Functions.ps1";
    $DistinguishedPath = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ","; # Get distinguished path

    Add-OrganizationalUnits -SourceFile ".\OrganizationalUnits.csv" -DistinguishedPath $DistinguishedPath; # Add Organizational Units to DC1
    Add-GroupsInAD -SourceFile ".\Groups.csv" -DistinguishedPath $DistinguishedPath; # Add groups to DC1
}

$FileServerSession = New-PSSession -ComputerName $Infrastructure[2].IpAddress -Credential (Get-Credential -Message "Enter credentials for $($Infrastructure[2].Name)" -UserName "intranet\Administrator");
$SecondaryDomainController = New-PSSession -ComputerName $Infrastructure[1].IpAddress -Credential (Get-Credential -Message "Enter credentials for $($Infrastructure[1].Name)" -UserName "intranet\Administrator");

# ~ Users ======================================================================================================================
# CREATE HOME AND RPOFILES
$Users = Import-Csv -Delimiter ";" -Path .\Users.csv; # Import Users from CSV file

foreach($user in $Users)
{
    if($User.Lastname -like "")
    {
        $Displayname = $User.Firstname
    }
    else
    {
        $Displayname = "$($User.Firstname).$($User.Lastname)";
    }

    if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "\\192.168.1.4\homes$\$($Displayname)" -Session $FileServerSession))
    {
        Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "\\192.168.1.4\homes$\$($Displayname)" -Session $FileServerSession;
    }

    if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "\\192.168.1.3\profiles$\$($Displayname)" -Session $SecondaryDomainController))
    {
        Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "\\192.168.1.3\profiles$\$($Displayname)" -Session $SecondaryDomainController;
    }
}

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Object_Functions.ps1";
    $DistinguishedPath = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ",";
    Add-UsersInAD -SourceFile ".\Users.csv" -DistinguishedPath $DistinguishedPath -HomePath "\\192.168.1.4\homes$\" -ProfilePath "\\192.168.1.3\profiles$\" ; # Add users to DC1
}


# TO DO: CREATE SHARES DEPARTMENTS BASED ON OUS WITH PERMISSIONS