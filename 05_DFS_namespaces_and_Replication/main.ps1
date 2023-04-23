# ~ Environment variables =======================================================================================
# Remote devices to connect to
$PrimaryDomainController = "203.113.11.1"; # Set the primary domain controller
$SecondaryDomainController = "203.113.11.2"; # Set the secondary domain controller
$MemberServer = "203.113.11.3"; # Set the member server



$NamespaceDetails = @{
    Name = "CompanyInfo";
    Domain = "intranet.mct.be";
    Links = @(
        @{
            targetName = "win03-ms"
            LinkFolder = "Recipes"
        },
        @{
            targetName = "win03-dc2"
            LinkFolder = "Menus"
        }
    );
}

$ReplicationGroupDetails = @{
    Name = "AllMenus";
    FolderName = "Menus";
    Members = @(
        "win03-dc2",
        "win03-ms"
    );
}


function Add-Roles
{
    <#
        .SYNOPSIS
        install the necessary roles

        .DESCRIPTION
        installs the necessary roles if they are not already installed

        .PARAMETER Roles
        The roles to install 

        .EXAMPLE
        Add-Roles -Roles @("DNS","DHCP")
    #>
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Roles
    );
    foreach ($Role in $Roles) 
    {
        if ((Get-WindowsFeature -Name $Role).Installed -eq $False) # Check if necessary roles are installed
        {
            Write-host "Installing $Role..."   
            Install-WindowsFeature -Credential (Get-Credential) -Name $Role -IncludeManagementTools
            Write-Host "$Role installed"
        }
        else
        {
            Write-Host "$Role already installed"
        }
    }
}

# ~  Install DFS Namespaces and Replication =======================================================================================
$PrimaryDomainControllerSession = New-PSSession -ComputerName $PrimaryDomainController -Credential  (Get-Credential -Message "Enter credentials for $PrimaryDomainController" -UserName "Administrator"); # Create a new session to the primary domain controller
$SecondaryDomainControllerSession = New-PSSession -ComputerName $SecondaryDomainController -Credential  (Get-Credential -Message "Enter credentials for $SecondaryDomainController" -UserName "Administrator"); # Create a new session to the secondary domain controller
$MemberServerSession = New-PSSession -ComputerName $MemberServer -Credential  (Get-Credential -Message "Enter credentials for $MemberServer" -UserName "Administrator"); # Create a new session to the member server


Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Add-Roles -Roles @("FS-DFS-Namespace", "RSAT-DFS-Mgmt-Con","FS-DFS-Replication");
} # Install the necessary roles + management tools on the primary domain controller (DFS-Namespace, DFS-Replication, RSAT-DFS-Mgmt-Con)


Invoke-Command -Session @($SecondaryDomainControllerSession, $MemberServerSession) -ScriptBlock {
    Add-Roles -Roles @("FS-DFS-Replication", "RSAT-DFS-Mgmt-Con");
} # Install the necessary roles + management tools on the secondary domain controller and member server (DFS-Replication, RSAT-DFS-Mgmt-Con)

# SOURCES: 
#   - https://learn.microsoft.com/en-us/windows-server/storage/dfs-namespaces/dfs-overview#to-install-dfs-by-using-windows-powershell
#   - https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview#install-dfs-replication-from-powershell





Start-Transaction;
try 
{
    # Create the new domain DFS namespace
    New-DfsnRoot -CimSession $PrimaryDomainControllerSession -Path "\\$($NamespaceDetails.Domain)\$($NamespaceDetails.NameSpace)" -Type DomainV2; # Create the new domain DFS namespace type DomainV2 (windows 2008 and higher)
   
    $NamespaceDetails.Links | ForEach-Object {
        New-DfsnFolder -CimSession $PrimaryDomainControllerSession -Path "\\$($NamespaceDetails.Domain)\$($NamespaceDetails.NameSpace)\$($_.LinkFolder)" -TargetPath "\\$($_.targetName)\$($_.LinkFolder)"; # Create the DFS link folder 'Recipes' with the target folder '\\winxx-dc2\recipes'
    } # Create the DFS link folders with the target folders
    
    Complete-Transaction;
}
catch 
{
    Write-Error "Could not setup DFS namespace: $_";
    Undo-Transaction;
}

# Undo the previous changes made to DFS

# .\Undo_DFSN_Changes.ps1 -Session $PrimaryDomainControllerSession -Domain $NamespaceDetails.Domain -Namespace $NamespaceDetails.NameSpace -Links $Links;



# Create the DFS Replication group
Start-Transaction;
try
{
    # Create the DFS Replication group
    New-DfsReplicationGroup -GroupName $ReplicationGroupDetails.Name -FolderName $ReplicationGroupDetails.FolderName -Members $ReplicationGroupDetails.Members

    # Force a sync for the replication group
    Get-DfsrMember -GroupName $ReplicationGroupDetails.Name | ForEach-Object {Sync-DfsReplicationGroup $_.ComputerName -GroupName $ReplicationGroupDetails.Name -SourceComputerName $_.ComputerName -Force};
    Complete-Transaction;
}
catch 
{
    Write-Error "Could not setup DFS replication: $_";
    Undo-Transaction;
}

# .\Undo_DFSR_Changes.ps1 -Session $PrimaryDomainControllerSession -GroupName $ReplicationGroupDetails.Name;