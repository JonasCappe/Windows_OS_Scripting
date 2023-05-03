
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
$DistinguishedPath = ""; # Distinguished path

# ~ PREPARE REMOTING ====================================================================================================
Write-Host "Preparing remoting on the local machine...";
# Check if the WMI service is running
if ((Get-Service -Name "Winmgmt").Status -ne "Running") {
    # If the service is not running, start it and set it to start automatically
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}
$Credential = (Get-Credential -Message "Enter credentials for remoteservers" -UserName "intranet\Administrator");
$TrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object -ExpandProperty Value; # Get the trusted hosts for remoting on the local machine
if(!($TrustedHosts -eq "192.168.1.*") -or $null -eq $TrustedHosts) # Check if the trusted hosts are set to the correct value
{
    Set-Item WSMan:\localhost\Client\TrustedHosts -Credential $Credential -Value "192.168.1.*" -Force; # Set the trusted hosts for remoting on the local machine
}

# ~ CREATE SESSIONS ====================================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $Infrastructure[0].IpAddress -Credential $Credential;
$FileServerSession = New-PSSession -ComputerName $Infrastructure[2].IpAddress -Credential $Credential;
$SecondaryDomainController = New-PSSession -ComputerName $Infrastructure[1].IpAddress -Credential $Credential;

# ~ Add UPN suffix ====================================================================================================
Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Create UPN suffix
    Get-ADForest | Set-ADForest -UPNSuffixes @{add="$using:UPN"}; # Add UPN suffix to Active Directory
    # Source: https://shellgeek.com/add-upn-suffix-in-active-directory/#Add_UPN_Suffix_in_Active_Directory_using_PowerShell
}

# ~ Create Shares ==================================================================================================
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process;
Set-Location "..\03_Windows_Active_Directory_Objects";
. ".\Object_Functions.ps1";

Add-Shares -SourceFile ".\SharesDc2.csv" -DestinationServer $Infrastructure[1].IpAddress; # Add shares to DC2
Add-Shares -SourceFile ".\SharesFileServer.csv" -DestinationServer $Infrastructure[2].IpAddress; # Add shares to FileServer

# ~ Organizatinal Units & Groups ======================================================================================================================
# Copy script & CSV's to Primary Domain Controller (DC1), for remote execution
Copy-Item -ToSession $PrimaryDomainControllerSession -Path ".\*" -Destination $RemotePath; # Copy script to Primary Domain Controller

$DistinguishedPath = Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Object_Functions.ps1";
    $Path = ((Get-ADForest | Select-Object -ExpandProperty PartitionsContainer).Split(',') | Where-Object { $_ -like "DC=*" }) -join ","; # Get distinguished path

    Add-OrganizationalUnits -SourceFile ".\OrganizationalUnits.csv" -DistinguishedPath $Path; # Add Organizational Units to DC1
    Add-GroupsInAD -SourceFile ".\Groups.csv" -DistinguishedPath $Path; # Add groups to DC1
    return $Path;
}

# ~ Users ======================================================================================================================
# CREATE HOME AND RPOFILES
$Users = Import-Csv -Delimiter ";" -Path .\Users.csv; # Import Users from CSV file

foreach($user in $Users)
{
    $DisplayName = (Get-UserDisplayName -UserFirstName $User.FirstName -UserLastname $User.Lastname); # Get display name

    # Create root share for home folders if it doesn't exist
    if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "\\$($Infrastructure[2].IpAddress)\homes$\$($Displayname)" -Session $FileServerSession))
    {
        Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "\\$($Infrastructure[2].IpAddress)\homes$\$($Displayname)" -Session $FileServerSession;
    }

    # Create root share for roaming user profiles folders if it doesn't exist
    if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "\\$($Infrastructure[1].IpAddress)\profiles$\$($Displayname)" -Session $SecondaryDomainController))
    {
        Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "\\$($Infrastructure[1].IpAddress)\profiles$\$($Displayname)" -Session $SecondaryDomainController;
    }
}

# ~ CREATE USERS ======================================================================================================================
# TODO: CLEAN UP CODE
Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Object_Functions.ps1";
    Add-UsersInAD -SourceFile ".\Users.csv" -DistinguishedPath $using:DistinguishedPath -HomePath "\\192.168.1.4\homes$\" -ProfilePath "\\192.168.1.3\profiles$\" ; # Add users to DC1
}

# Retrieve user priciple names
$UserPrincipleNames = Invoke-Command -ScriptBlock { return (Get-ADUser -Filter * -SearchBase "ou=intranet,dc=intranet,dc=mct,dc=be" | Select-Object -ExpandProperty UserPrincipalName) } -Session $PrimaryDomainControllerSession;

Invoke-Command -Session $FileServerSession -ScriptBlock {
    # Set permission on home folder
    foreach($UserPrincipleName in $using:UserPrincipleNames)
    {
        Write-Host "\\$($using:Infrastructure[2].IpAddress)\homes$\$($UserPrincipleName)"
        $ACL = (Get-ACL "\\$($using:Infrastructure[2].IpAddress)\homes$\$($UserPrincipleName)");
        ## Enable inheritance and copy permissions
        $ACL.SetAccessRuleProtection($False, $True);
        # Setting Modify for the User account
        $SecurityPrincipal = $UserPrincipleName;
        $NtfsPermission = "Modify";
        $Inheritance = "ContainerInherit, ObjectInherit";
        $Propagation = "None";
        $AccessControlType = "Allow";
    
        $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$SecurityPrincipal", "$NtfsPermission", "$Inheritance","$Propagation","$AccessControlType"))); # Create new access rule for Security Principal and add it to ACL
        
        Set-Acl -Path "\\$($using:Infrastructure[2].IpAddress)\homes$\$($UserPrincipleName)" -AclObject $ACL;
            
    }
}


# CREATE WITH DEPARTMENTS
$folders = Import-Csv -Delimiter ";" -Path .\folders.csv; # Import Users from CSV file
Invoke-Command -Session $FileServerSession -ScriptBlock {

    foreach($Folder in $using:folders) 
    {
        if (-not (Test-Path -Path $Folder.Path ))
        {
            New-Item -ItemType Directory -Path $Folder.Path;
           
        }
        $ACL = (Get-ACL $Folder.Path);
        $SecurityPrincipal = $Folder.NtfsPermission.Split(':')[0];
        $NtfsPermission = $Folder.NtfsPermission.Split(':')[1];
        $Inheritance = $Folder.Inheritance;
        $Propagation = $Folder.Propagation;
        $AccessControlType = $Folder.AccessControlType;

        $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$SecurityPrincipal", "$NtfsPermission", "$Inheritance","$Propagation","$AccessControlType"))); # Create new access rule for Security Principal and add it to ACL
        

        Set-Acl -Path $Folder.Path -AclObject $ACL; # Set ACL of share
    }
}

