# ~ GLOBAL VARIABLES ====================================================================================================
$Infrastructure = @(
    @{
        Name = "DC1"
        IP = "203.113.11.1"
    }
    @{
        Name = "DC2"
        IP = "203.113.11.2"
    }
    @{
        Name = "MS"
        IP = "203.113.11.3"
    }
); # Remote machines
$UPN = "mct.be" # UPN suffix

# ~ Add UPN suffix ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[0].Name)" -UserName "Administrator");

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Create UPN suffix
    Get-ADForest | Set-ADForest -UPNSuffixes @{add="$UPN"}; # Add UPN suffix to Active Directory
    # Source: https://shellgeek.com/add-upn-suffix-in-active-directory/#Add_UPN_Suffix_in_Active_Directory_using_PowerShell
}

# ~ Create Shares ==================================================================================================
. ".\Object_Functions.ps1"

Add-Shares -SourceFile ".\SharesDc2.csv" -DestinationServer $Infrastructure[1].Name; # Add shares to DC2
Add-Shares -SourceFile ".\SharesFileServer.csv" -DestinationServer $Infrastructure[2].Name; # Add shares to FileServer

# ~ Organizatinal Units & Groups ======================================================================================================================
# Copy script to Primary Domain Controller (DC1), for remote execution
Copy-Item -ToSession $PrimaryDomainControllerSession -Path ".\*" -Destination "C:\temp\*"; # Copy script to Primary Domain Controller

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    . ".\Object_Functions.ps1"
    $DistinguishedPath = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ",";

    Add-OrganizationalUnits -SourceFile ".\OrganizationalUnits.csv" -DistinguishedPath $DistinguishedPath; # Add Organizational Units to DC1
    Add-GroupsInAD -SourceFile ".\Groups.csv" -DistinguishedPath $DistinguishedPath; # Add groups to DC1
}

# ~ Users ======================================================================================================================
Add-UsersInAD -SourceFile ".\Users.csv" -DestinationServer $Infrastructure[0].Name; # Add users to DC1

# TO DO: CREATE SHARES DEPARTMENTS BASED ON OUS WITH PERMISSIONS