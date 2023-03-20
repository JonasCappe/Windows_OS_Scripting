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

    $ServerSession = New-PSSession -ComputerName $DestinationServer -Credential  (Get-Credential -Message "Enter credentials for $($DestinationServer)" -UserName "Administrator");

    # Create the share containing the users home folders. (Tip:New-SmbShare, Get-Acl, SetAccessRuleProtection, Set-Acl, ...)
    $Shares = Import-Csv -Delimiter ";" -Path ".\MainShares.csv"; # Import Shares from CSV file
    foreach($Share in $Shares)
    {
        if (-not (Invoke-Command -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList $Share.Path -Session $ServerSession))
        {
            Invoke-Command -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $Share.Path -Session $ServerSession;
        }
        #Check if share already exists, if not create it
        if (-not (Invoke-Command -ScriptBlock { Get-SmbShare -Name $args[0] } -ArgumentList $Share.Name -Session $ServerSession))
        {
            New-SmbShare -Name $Share.Name -Path $Share.Path -FullAccess $Share.FolderPermissions -CimSession $ServerSession;
        }
            else
        {
            Write-Host "Share $Share.Name already exists";
        }
        # Set ACL of share, remove all access rules and add specified access rules
        $ACL = Get-Acl -Path "\\$($Infrastructure[0].Name)\$($Share.Name)"; # Get ACL of share
        $ACL.SetAccessRuleProtection($true, $false); # Disable inheritance
        $ACL.Access | ForEach-Object { $ACL.RemoveAccessRule($_) } # Remove all access rules
        #$Security = $Share.NtfsPermission.split(",")[0].Split(":");
        #$NtfsPermission = $Share.NtfsPermission.split(",")[1].Split(":").replace("|",",");
        foreach($Permission in $Share.NtfsPermission.split(",")) # Loop through all permissions, to create access rules
        {
            $SecurityPrincipal = $Permission.split(":")[0]; # Get Security Principal
            $NtfsPermission = $Permission.split(":")[1].replace("|",","); # Get Ntfs Permission
            $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SecurityPrincipal, "$NtfsPermission", "Allow"))); # Create new access rule for Security Principal and add it to ACL
        }
        Set-Acl -Path "\\$($Infrastructure[0].Name)\$($Share.Name)" -AclObject $ACL; # Set ACL of share
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
    #>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationServer,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedPath

    );

    $ServerSession = New-PSSession -ComputerName $DestinationServer -Credential  (Get-Credential -Message "Enter credentials for $($DestinationServer)" -UserName "Administrator");
    $Users = Import-Csv -Delimiter ";" -Path "C:\temp\Users.csv"; # Import Users from CSV file
    Invoke-Command -Session $ServerSession -ScriptBlock { 
        foreach ($User in $using:Users) 
        {
            # Extract data from CSV file
            $Surname = $User.Lastname;
            $Givenname = $User.Firstname;
            $Displayname = $Givenname + "." + $Surname;
            $UPNUser = $Displayname+$UPN;
            $Title = $User.JobTitle
            $Password = $User.Password
            $Department = $User.Department
            $Path = "OU=" + $Department + ",OU=intranet,$DistinguishedPath"
            $GroupName = "OU=" + $User.GroupName+",$DistinguishedPath";
            $DistinguishedName = "CN=" + $Displayname + "," + $Path;

            New-ADUser -Name $Displayname `
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
            -ProfilePath "\\$($Infrastructure[1].Name)\Profiles\$($Displayname)";

            Add-ADGroupMember $GroupName $DistinguishedName;
        }
    }
    
} # Based on NWB SCRIPT - Supplemented by info from https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps
