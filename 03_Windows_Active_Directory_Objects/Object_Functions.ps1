
$Domain = $env:USERDOMAIN;
function Add-Shares
{
    <#
        .SYNOPSIS
        Add shares with permissions to a server from a CSV file.
        .DESCRIPTION
        Add shares with permissions to a server from a CSV file.
        .PARAMETER SourceFile
        The path to the CSV file containing the shares to add.
        .PARAMETER DestinationServer
        The name or IP address of the server to add the shares to.
        .EXAMPLE
        Add-Shares -SourceFile ".\SharesFileServer.csv" -DestinationServer "FileServer";
        .NOTES
        CSV file should be formatted as follows:
        Name;Path;FolderPermissions;NtfsPermission
        Diffrerent permissions can be added by separating them with a comma.
        Home$;C:\homes;Everyone;Domain Admins:Full Control,Authenticated Users:ReadAndExecute|SynchronizeProfiles$;C:\profiles;Everyone;Domain Admins:Full Control,Authenticated Users:ReadAndExecute|Synchronize

    #>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationServer
    );

    $ServerSession = New-PSSession -ComputerName $DestinationServer -Credential (Get-Credential -Message "Enter credentials for $($DestinationServer)" -UserName "intranet\Administrator");

    # Create the share containing the users home folders. (Tip:New-SmbShare, Get-Acl, SetAccessRuleProtection, Set-Acl, ...)
    $Shares = Import-Csv -Delimiter ";" -Path $SourceFile; # Import Shares from CSV file
    foreach($Share in $Shares)
    {
        if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList $Share.Path -Session $ServerSession)) # Check if path exists, if not create it
        {
            Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $Share.Path -Session $ServerSession;
        }
        
        #Check if share already exists, if not create it
        if ($null -eq (Invoke-Command -ScriptBlock { Get-SmbShare -Name $args[0] -ErrorAction SilentlyContinue } -ArgumentList $Share.Name -Session $ServerSession))
        {
            Invoke-Command -Session $ServerSession -ScriptBlock { 
                New-SmbShare -Name $using:Share.Name -Path $using:Share.Path -FullAccess $using:Share.FolderPermissions

                $ACL = Get-Acl -Path "\\$($using:DestinationServer)\$($using:Share.Name)"; # Get ACL of share
                $ACL.SetAccessRuleProtection($true, $false); # Disable inheritance
                $ACL.Access | ForEach-Object { $ACL.RemoveAccessRule($_) } # Remove all access rules
            };
        }
        else
        {
            Write-Host "Share $Share.Name already exists";
        }
        # Set ACL of share, remove all access rules and add specified access rules
        Invoke-Command -Session $ServerSession -ScriptBlock {
            
            $Share = $using:Share;
            $SecurityPrincipal = $Share.NtfsPermission.Split(":")[0];
            $NtfsPermission = $Share.NtfsPermission.Split(":")[1];
            $Inheritance = $Share.Inheritance;
            $Propagation = $Share.Propagation;
            $AccessControlType = $Share.AccessControlType;
            $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$SecurityPrincipal", "$NtfsPermission", "$Inheritance","$Propagation","$AccessControlType"))); # Create new access rule for Security Principal and add it to ACL
            
            Set-Acl -Path "\\$($using:DestinationServer)\$($using:Share.Name)" -AclObject $ACL; # Set ACL of share
        }
    }
    <#
    Sources: 
    - https://docs.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=win10-ps
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.1
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.1
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-accessruleprotection?view=powershell-7.1
    #>
}

function Add-UsersInAD
{
    <#
    .SYNOPSIS
    Add users to Active Directory from a CSV file.
    .DESCRIPTION
    Add users to Active Directory from a CSV file.
    .PARAMETER SourceFile
    The path to the CSV file containing the users to add.
    .PARAMETER DestinationServer
    The name or IP address of the server to add the users to.
    .PARAMETER DistinguishedPath
    The distinguished path of the DC to add the users to.
    .EXAMPLE
    Add-UsersInAD -SourceFile ".\Users.csv" -DestinationServer "DC01" -DistinguishedPath "DC=intranet,DC=contoso,DC=com";
    .NOTES
    CSV file should be formatted as follows:
    FirstName;Lastname;Department;Password;JobTitle;Company;GroupName
    #>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedPath,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$HomePath,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfilePath

    );

    #$ServerSession = New-PSSession -ComputerName $DestinationServer -Credential (Get-Credential -Message "Enter credentials for $($DestinationServer)" -UserName "Administrator");
   Start-Transaction;
   try
   {
     
    $Users = Import-Csv -Delimiter ";" -Path $SourceFile; # Import Users from CSV file
    
    foreach ($User in $Users) 
    {
        # Extract data from CSV file
        $Surname = $User.Lastname;
        $Givenname = $User.Firstname;
        if($Surname -like "")
        {
            $Displayname = $Givenname
        }
        else
        {
            $Displayname = $Givenname + "." + $Surname;
        }
        $UPNUser = $Displayname+$UPN;
        $Title = $User.JobTitle
        $Password = $User.Password
        $Department = $User.Department
        $Path = "OU=" + $Department + ",OU=intranet,$DistinguishedPath";
        $DistinguishedName = "CN=" + $Displayname + "," + $Path;
        $HomeDir = "$($HomePath)$($DisplayName)";
        $Profile = "$($ProfilePath)$($DisplayName)";
        
   
        try
        {
            Get-ADUser -Identity $UPNUser | Out-Null;
            Write-Host "User with identity $($UPNUser) already exist" -ForegroundColor Yellow;
        }
        catch
        {
            Write-Host "Creating user $($UPNUser)" -ForegroundColor Green;
            New-ADUser -Name $Displayname `
            -UserPrincipalName $UPNUser `
            -GivenName $Givenname `
            -Surname $Surname `
            -Displayname $Displayname `
            -EmailAddress $UPNUser `
            -Title $Title `
            -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -Enabled $true `
            -ChangePasswordAtLogon $false `
            -PasswordNeverExpires $true `
            -UserPrincipalName $UpnUser `
            -EmailAddress $UpnUser `
            -Path $Path `
            -HomeDirectory $HomeDir `
            -ProfilePath $Profile;
            
            foreach($Group in $User.GroupName.Split(','))
            {
                Write-Host $DistinguishedName;
                Get-ADGroup -Filter { name -eq $Group } | Add-ADGroupMember -members $DistinguishedName;
                
            }
             
        }
        
    }
    Complete-Transaction;
   }
   catch
   {
        Write-Error "Error could not create users: $_";
        Undo-Transaction;
   }
        
} # Based on NWB SCRIPT - Supplemented by info from https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps

function Add-GroupsInAD
{
    <#
        .SYNOPSIS
        Add groups to Active Directory from a CSV file.
        .DESCRIPTION
        Add groups to Active Directory from a CSV file.
        .PARAMETER SourceFile
        The path to the CSV file containing the groups to add.
        .PARAMETER DistinguishedPath
        The distinguished path of the DC to add the groups to.
        .EXAMPLE
        Add-GroupsInAD -SourceFile ".\Groups.csv" -DistinguishedPath "DC=intranet,DC=contoso,DC=com";
        .NOTES
        CSV file should be formatted as follows:
        GroupName;Scope;Category;MemberOf;Path
        GG-BOARD;Global;Security;DLG-BOARD;OU=Board,OU=intranet
        DLG-MARKETING;DomainLocal;Security;;OU=Marketing,OU=intranet
    #>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedPath

    );

    # Create Groups if they not exist
    $Groups = Import-Csv -Delimiter ";" -Path $SourceFile; # Import Groups from CSV file

    foreach ($Group in $Groups)
    {
        $ouPath = "$($Group.Path),$($DistinguishedPath)"; # format path to be used in New-ADOrganizationalUnit
        Write-Host "CN=$($Group.GroupName),$($ouPath)";

        #Check if exists
        if ($null -ne (Get-ADGroup -Filter { DistinguishedName -like "CN=$($Group.GroupName),$($ouPath)" } -ErrorAction SilentlyContinue)) # If Group exists, skip
        {
            Write-Host "Group '$($Group.GroupName)' already exists in '$($Group.Path)'" -ForegroundColor Yellow;
        }
        else # If Group doesn't exist, create it
        {
            Write-Host "Creating Group '$($Group.GroupName)' in '$($Group.Path)'" -ForegroundColor Green;
            New-ADGroup -Name $Group.GroupName -Path $ouPath -GroupScope $Group.Scope -GroupCategory $Group.Category;
            if("" -ne $Group.MemberOf)
            {
                if($Group.MemberOf -like "* *")
                {
                   foreach($MemberSchip in $Group.MemberOf.Split(" "))
                   {
                        Add-ADGroupMember -Identity $MemberSchip -Members $Group.GroupName;
                   } 
                }
                else
                {
                    Add-ADGroupMember -Identity $Group.MemberOf -Members $Group.GroupName;
                }
            }
                
        }    
    }

}


function Add-OrganizationalUnits
{
    <#
        .SYNOPSIS
        Add Organizational Units to Active Directory from a CSV file.
        .DESCRIPTION
        Add Organizational Units to Active Directory from a CSV file.
        .PARAMETER SourceFile
        The path to the CSV file containing the Organizational Units to add.
        .PARAMETER DistinguishedPath
        The distinguished path of the DC to add the Organizational Units to.
        .EXAMPLE
        Add-OrganizationalUnits -SourceFile ".\OrganizationalUnits.csv" -DistinguishedPath "DC=intranet,DC=contoso,DC=com";
        .NOTES
        CSV file should be formatted as follows:
        Name;Path
        Projects;OU=intranet
    #>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedPath

    );

    
    try {
        $Parent = Import-Csv -Delimiter ";" -Path $SourceFile | Select-Object -First 1
        $OrganizationalUnits = Import-Csv -Delimiter ";" -Path $SourceFile | Where-Object { $_.Name -ne $Parent.Name }
        Write-Host "OU=$($Parent.Name),$($DistinguishedPath)"
        Write-Host ($null -eq (Get-ADOrganizationalUnit -Filter { DistinguishedName -like "OU=$($Parent.Name),$($DistinguishedPath)" } ))
        
        if ($null -eq (Get-ADOrganizationalUnit -Filter { DistinguishedName -like "OU=$($Parent.Name),$($DistinguishedPath)" } )) 
        {
            Write-Verbose "Organizational Unit $($Parent.Name) does not exist in $($DistinguishedPath)"
            Write-Verbose "Creating Organizational Unit $($Parent.Name) in $($DistinguishedPath)"
            New-ADOrganizationalUnit -Name $Parent.Name -Path $DistinguishedPath
        }


        foreach ($OrganizationalUnit in $OrganizationalUnits) 
        {
           write-host "OU=$($OrganizationalUnit.Name),OU=$($Parent.Name),$($DistinguishedPath)"

            if ($null -ne (Get-ADOrganizationalUnit -Filter { DistinguishedName -like "OU=$($OrganizationalUnit.Name),OU=$($Parent.Name),$($DistinguishedPath)" }))
            {
                Write-Host "Organizational Unit $($OrganizationalUnit.Name) already exists in $($OrganizationalUnit.Path)" -ForegroundColor Yellow;
            }
            else
            {
                Write-Host "Creating Organizational Unit $($OrganizationalUnit.Name) in $($OrganizationalUnit.Path)" -ForegroundColor Green;
                New-ADOrganizationalUnit -Name $OrganizationalUnit.Name -Path "OU=$($Parent.Name),$($DistinguishedPath)";
            }
        }
    }
    catch 
    {
        Write-Error $_.Exception.Message
    }
}

function Get-UserDisplayName
{
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserFirstName,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true,position=1)]
        [string]$UserLastName=""
    );
    
    if($User.Lastname -like "") # 
    {
        $Displayname = $UserFirstName;
    }
    else
    {
        $Displayname = "$($UserFirstName).$($UserLastName)";
    }
    return $DisplayName;
}
