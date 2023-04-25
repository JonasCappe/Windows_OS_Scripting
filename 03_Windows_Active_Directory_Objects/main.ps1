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

# ~ Add UPN suffix ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].IpAddress -Credential (Get-Credential -Message "Enter credentials for $($Infrastructure[0].Name)" -UserName "Administrator");

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
    . ".\Object_Functions.ps1"
    $DistinguishedPath = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ","; # Get distinguished path

    Add-OrganizationalUnits -SourceFile ".\OrganizationalUnits.csv" -DistinguishedPath $DistinguishedPath; # Add Organizational Units to DC1
    #Add-GroupsInAD -SourceFile ".\Groups.csv" -DistinguishedPath $DistinguishedPath; # Add groups to DC1
}

# ~ Users ======================================================================================================================
Add-UsersInAD -SourceFile ".\Users.csv" -DestinationServer $Infrastructure[0].Name; # Add users to DC1

# TO DO: CREATE SHARES DEPARTMENTS BASED ON OUS WITH PERMISSIONS