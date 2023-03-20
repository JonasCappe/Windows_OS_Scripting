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
);
$UPN = "mct.be"
# ~ PrimaryDomainController ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[0].Name)" -UserName "Administrator");

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Create UPN suffix
    Get-ADForest | Set-ADForest -UPNSuffixes @{add="$UPN"};
    # Source: https://shellgeek.com/add-upn-suffix-in-active-directory/#Add_UPN_Suffix_in_Active_Directory_using_PowerShell
}

# ~ Create Shares ==================================================================================================
. ".\Object_Functions.ps1"

Add-Shares -SourceFile ".\SharesDc2.csv" -DestinationServer $Infrastructure[1].Name; # Add shares to DC2
Add-Shares -SourceFile ".\SharesFileServer.csv" -DestinationServer $Infrastructure[2].Name; # Add shares to FileServer

Copy-Item -ToSession $PrimaryDomainControllerSession -Path ".\*" -Destination "C:\temp\*"; # Copy script to Primary Domain Controller

# ~ Organizatinal Units ======================================================================================================================
Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    $OrganizationalUnits = Import-Csv -Delimiter ";" -Path ".\OrganizationalUnits.csv"; # Import Organizational Units from CSV file
    $DC = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ",";

    # Create Organizational Units if they don't exist
    foreach ($OrganizationalUnit in $OrganizationalUnits)
    {
        $ouPath = ($OrganizationalUnit.Path -replace ";", ",") + "," + $DC; # format path to be used in New-ADOrganizationalUnit

        #Check if exists
        if (Get-ADOrganizationalUnit -Filter { DistinguishedName -like $ouPath } -ErrorAction SilentlyContinue) # If Organizational Unit exists, skip
        {
            Write-Host "Organizational Unit '$($OrganizationalUnit.Name)' already exists in '$($OrganizationalUnit.Path)'" -ForegroundColor Yellow;
        }
        else # If Organizational Unit doesn't exist, create it
        {
            Write-Host "Creating Organizational Unit '$($OrganizationalUnit.Name)' in '$($OrganizationalUnit.Path)'" -ForegroundColor Green;
            New-ADOrganizationalUnit -Name $OrganizationalUnit.Name -Path $ouPath; 
        }    
    }

    # Create Groups if they not exist
    $Groups = Import-Csv -Delimiter ";" -Path ".\Groups.csv"; # Import Groups from CSV file

    foreach ($Group in $Groups)
    {
        $ouPath = ($Group.Path -replace ";", ",") + "," + $DC; # format path to be used in New-ADOrganizationalUnit

        #Check if exists
        if (Get-ADGroup -Filter { DistinguishedName -like $ouPath } -ErrorAction SilentlyContinue) # If Group exists, skip
        {
            Write-Host "Group '$($Group.Name)' already exists in '$($Group.Path)'" -ForegroundColor Yellow;
        }
        else # If Group doesn't exist, create it
        {
            Write-Host "Creating Group '$($Group.Name)' in '$($Group.Path)'" -ForegroundColor Green;
            New-ADGroup -Name $Group.Name -Path $ouPath -GroupScope $Group.Scope -GroupCategory $Group.Category;
            Add-ADGroupMember -Identity $Group.MemberOf -Members $Group.Name;    
        }    
    }
    
    $Users = Import-Csv -Delimiter ";" -Path "C:\temp\Users.csv"; # Import Users from CSV file

    foreach ($User in $Users) 
    {
        # Extract data from CSV file
        $Surname = $User.Lastname;
        $Givenname = $User.Firstname;
        $Displayname = $Givenname + "." + $Surname;
        $UPNUser = $Displayname+$UPN;
        $Title = $User.JobTitle
        $Password = $User.Password
        $Department = $User.Department
        $Path = "OU=" + $Department + ",OU=intranet,$DC"
        $GroupName = "OU=" + $User.GroupName+",$DC";
        $DistinguishedName = "CN=" + $Displayname + "," + $Path;

        New-ADUser -Name $Displayname ``
        -UserPrincipalName $UPNUser `
        -GivenName $Givenname `
        -Surname $Surname `
        -Displayname $Displayname `
        -EmailAddress $UPNUser `
        -Title $Title
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -Enabled $true `
        -ChangePasswordAtLogon $true `
        -PasswordNeverExpires `
        -Path $Path
        -HomeDirectory "\\$($Infrastructure[2].Name)\Homes\$($Displayname)" `
        -ProfilePath "\\$($Infrastructure[1].Name)\Profiles\$($Displayname)" `;

        Add-ADGroupMember $GroupName $DistinguishedName;
    }
} # Based on NWB SCRIPT - Supplemented by info from https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps