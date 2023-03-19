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
# ~ PrimaryDomainController ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[0].Name)" -UserName "Administrator");

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Create UPN suffix
    Get-ADForest | Set-ADForest -UPNSuffixes @{add="$UPN"};
    # Source: https://shellgeek.com/add-upn-suffix-in-active-directory/#Add_UPN_Suffix_in_Active_Directory_using_PowerShell
}

# ~ MemberServer - Fileserver ==================================================================================================
$MemberServerSession = New-PSSession -ComputerName $Infrastructure[2].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[2].Name)" -UserName "Administrator");

# Create the share containing the users home folders. (Tip:New-SmbShare, Get-Acl, SetAccessRuleProtection, Set-Acl, ...)
New-SmbShare -Name "Homes$" -Path "C:\homes" -FullAccess "Everyone" -CimSession $MemberServerSession;


$ACL = Get-Acl -Path \\$($Infrastructure[2].Name)\Homes$; # Get ACL of share
$ACL.SetAccessRuleProtection($true, $false); # Disable inheritance

$ACL.Access | ForEach-Object { $ACL.RemoveAccessRule($_) } # Remove all access rules

$AdminPermission = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", "FullControl", "Allow"); # Create new access rule for Domain Admins
$AuthUsersPermission = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute, Synchronize", "Allow"); # Create new access rule for Authenticated Users

# Add access rules to ACL
$ACL.AddAccessRule($AdminPermission);
$ACL.AddAccessRule($AuthUsersPermission);

Set-Acl -Path \\$($Infrastructure[2].Name)\Homes$ -AclObject $ACL; # Set ACL of share

# ~ SecondaryDomainController =================================================================================================
$SecondaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[1].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[1].Name)" -UserName "Administrator");

# Create the share containing the users profile folders (roaming profiles). (Tip:New-SmbShare, Get-Acl, SetAccessRuleProtection, Set-Acl, ...)
New-SmbShare -Name "Profiles$" -Path "C:\profiles" -FullAccess "Everyone" -CimSession $SecondaryDomainControllerSession;

$ACL = Get-Acl -Path \\$($Infrastructure[1].Name)\Profiles$; # Get ACL of share

$ACL.SetAccessRuleProtection($true, $false); # Disable inheritance

$ACL.Access | ForEach-Object { $ACL.RemoveAccessRule($_) } # Remove all access rules

$AdminPermission = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", "FullControl", "Allow"); # Create new access rule for Domain Admins
$AuthUsersPermission = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute, Synchronize", "Allow"); # Create new access rule for Authenticated Users

# Add access rules to ACL
$ACL.AddAccessRule($AdminPermission);
$ACL.AddAccessRule($AuthUsersPermission);

Set-Acl -Path \\$($Infrastructure[1].Name)\Profiles$ -AclObject $ACL; # Set ACL of share


# ~ Domain ======================================================================================================================

$UPN = "mct.be";
$CompanyName = "ABC";
$CompanyOUPath = "OU=$companyName,DC=contoso,DC=com"





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

#Create Groups if they not exist
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
    }    
}

$Users = Import-Csv -Delimiter ';' -Path L:\Users.csv

foreach ($User in $Users)
{
    $Surname = $User.Surname
    $Givenname = $User.Givenname

    $Displayname = $Givenname + " " + $Surname

    Read-Host 'Geef Domain op' $Domein
    $UPN = $Displayname.Substring(0,1) + $Surname + '@' + $Domein


    $StreetAddress = $User.StreetAddres
    $City = $User.City
    $Title = $User.Title
    $Password = $User.Password
    $Country = $User.Country
    $Phonenumber = $User.TelephoneNumber
    $Department = $User.Department
    $Path = "OU=" + $Department + ",OU=$OU,DC=$DC,DC=$SUFFIX"


    New-ADUser -Name $Displayname -UserPrincipalName $UPN -GivenName $Givenname -Surname $Surname -Displayname $Displayname -EmailAddress $UPN -StreetAddress $StreetAddress -City $City -Title $Title
    -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $true -ChangePasswordAtLogon $true -PasswordNeverExpires $true -Country $Country -Path $Path -OfficePhone $Phonenumber
}