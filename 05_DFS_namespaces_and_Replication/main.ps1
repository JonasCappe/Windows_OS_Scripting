# ~ Environment variables =======================================================================================
# Remote devices to connect to
$PrimaryDomainController = "192.168.1.2"; # Set the primary domain controller
$SecondaryDomainController = "192.168.1.3"; # Set the secondary domain controller
$MemberServer = "192.168.1.4"; # Set the member server


# Paths to the scripts
$LocalScripts = '..\02_Install_Roles\*';
$RemotePath = "C:\temp"; # Remote path

# Credentials and sessions
$Credential = (Get-Credential -Message "Enter credentials for the remote servers" -UserName "intranet\Administrator");

$PrimaryDomainControllerSession = New-PSSession -ComputerName $PrimaryDomainController -Credential $Credential; # Create a new session to the primary domain controller
$SecondaryDomainControllerSession = New-PSSession -ComputerName $SecondaryDomainController -Credential $Credential; # Create a new session to the secondary domain controller
$MemberServerSession = New-PSSession -ComputerName $MemberServer -Credential $Credential; # Create a new session to the member server

# Copy install role script, for remote execution
Copy-Item -ToSession $PrimaryDomainControllerSession -Path $LocalScripts -Destination $RemotePath; # Copy script to Primary Domain Controller
Copy-Item -ToSession $SecondaryDomainControllerSession -Path $LocalScripts -Destination $RemotePath; # Copy script to Secondary Domain Controller
Copy-Item -ToSession $MemberServerSession -Path $LocalScripts -Destination $RemotePath; # Copy script to Fileserver

# ~  Install DFS Namespaces and Replication =======================================================================================
Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Install-Roles.ps1";

    Add-Roles -Roles @("FS-DFS-Namespace", "RSAT-DFS-Mgmt-Con","FS-DFS-Replication");
} # Install the necessary roles + management tools on the primary domain controller (DFS-Namespace, DFS-Replication, RSAT-DFS-Mgmt-Con)


Invoke-Command -Session @($SecondaryDomainControllerSession, $MemberServerSession) -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Install-Roles.ps1";

    Add-Roles -Roles @("FS-DFS-Replication", "RSAT-DFS-Mgmt-Con");
} # Install the necessary roles + management tools on the secondary domain controller and member server (DFS-Replication, RSAT-DFS-Mgmt-Con)
# SOURCES: 
#   - https://learn.microsoft.com/en-us/windows-server/storage/dfs-namespaces/dfs-overview#to-install-dfs-by-using-windows-powershell
#   - https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview#install-dfs-replication-from-powershell

# ~ Disributed File System Namespace (DFS) ========================================================================================
$NamespaceDetails = @{
    Name = "CompanyInfo";
    Domain = "intranet.mct.be";
    targetName = "win13-dc1"
    LocalPath = "C:\DFSRoots\CompanyInfo"
    Links = @(
        @{
            targetName = "win03-ms"
            LinkFolder = "ABC$"
            LocalPath = "C:\ABC$"
        },
        @{
            targetName = "win03-ms"
            LinkFolder = "Recipes"
            LocalPath = "C:\Recipes"
        },
        @{
            targetName = "win03-dc2"
            LinkFolder = "Menus"
            LocalPath = "C:\Menus"
        }
    );
};
# ~  Create new DFS Namespace & Create LinkerdFolders =======================================================================================
Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    Start-Transaction;
    try 
    {
        # Create DFSRootFolder with namespace folder if not exists
        if(-not(Test-Path $using:NamespaceDetails.LocalPath))
        {
            New-Item -Path $using:NamespaceDetails.LocalPath -ItemType Directory | Out-Null
        }
        # Create main share if not exists
        if(-not(Get-SmbShare -Name $using:NamespaceDetails.Name -ErrorAction SilentlyContinue))
        {
           New-SmbShare -Path $using:NamespaceDetails.LocalPath -Name $using:NamespaceDetails.Name -FullAccess Everyone | Out-Null
        }

        # Create new domain DFS  namespace if not exists
        if(-not(Get-DfsnRoot -Path "\\$($using:NamespaceDetails.Domain)\$($using:NamespaceDetails.Name)" -ErrorAction SilentlyContinue))
        {
           New-DfsnRoot -Path "\\$($using:NamespaceDetails.Domain)\$($using:NamespaceDetails.Name)" -Type DomainV2 -TargetPath "\\$($env:COMPUTERNAME)\$($using:NamespaceDetails.Name)"; 
        }

        # Create DFS Link folders with target folders
        $using:NamespaceDetails.Links | ForEach-Object {
          
            New-DfsnFolder -Path "\\$($using:NamespaceDetails.Domain)\$($using:NamespaceDetails.Name)\$($_.LinkFolder)" -TargetPath "\\$($_.targetName)\$($_.LinkFolder)"; # Create the DFS link folder
        }
    }
    catch 
    {
        Write-Error "Could not setup DFS namespace: $_";
        Undo-Transaction;
    }     
};

# Undo the previous changes made to DFS

# .\Undo_DFSN_Changes.ps1 -Session $PrimaryDomainControllerSession -Domain $NamespaceDetails.Domain -Namespace $NamespaceDetails.Name -Links $Links;

# ~ Distributed File System Replication (DFSR) =======================================================================================
$ReplicationGroupDetails = @{
    Name = "Menus";
    Domain = "intranet.mct.be"
    FolderName = "Menus";
    Members = @(
        "win03-dc2",
        "win03-ms"
    );
    ContentPath = "C:\Menus";
       
    
}

# Create the DFS Replication group
Invoke-Command -ComputerName "win13-dc1" -Credential $Credential -Authentication Kerberos -ScriptBlock {
    Start-Transaction;
    try
    {
        # Create the DFS Replication group
        if(-not(Get-DfsReplicationGroup -GroupName $using:ReplicationGroupDetails.Name -ErrorAction SilentlyContinue))
        {
            New-DfsReplicationGroup -GroupName $using:ReplicationGroupDetails.Name -DomainName $using:ReplicationGroupDetails.Domain  -ErrorAction Stop;
        }
        
        $using:ReplicationGroupDetails.Members | ForEach-Object {
            if(-not(Get-DfsrMember -GroupName $using:ReplicationGroupDetails.Name | Where-object ComputerName -eq $_))
            {
                Add-DfsrMember -ComputerName "$_" -GroupName $using:ReplicationGroupDetails.Name -DomainName $using:ReplicationGroupDetails.Domain -ErrorAction Stop;
            }
            
        }
        
        

        if(-not(Get-DfsReplicatedFolder -GroupName $using:ReplicationGroupDetails.Name  -FolderName $using:ReplicationGroupDetails.FolderName -ErrorAction SilentlyContinue))
        {
            New-DfsReplicatedFolder -FolderName $using:ReplicationGroupDetails.FolderName -GroupName $using:ReplicationGroupDetails.Name -DfsnPath "\\$($using:ReplicationGroupDetails.Domain)\$($using:ReplicationGroupDetails.Name)" -ErrorAction Stop;
        }
    
        if(-not(Get-DfsrConnection -GroupName $using:ReplicationGroupDetails.Name -SourceComputerName $using:ReplicationGroupDetails.Members[0] -DestinationComputerName $using:ReplicationGroupDetails.Members[1]))
        {
            Add-DfsrConnection -SourceComputerName $using:ReplicationGroupDetails.Members[0] -DestinationComputerName $using:ReplicationGroupDetails.Members[1] -GroupName $using:ReplicationGroupDetails.Name -ErrorAction Stop;
        }
        
        
        $using:ReplicationGroupDetails.Members | ForEach-Object {
    
            Set-DfsrMembership -ComputerName $_ -FolderName $using:ReplicationGroupDetails.FolderName -GroupName $using:ReplicationGroupDetails.Name -ContentPath $using:ReplicationGroupDetails.ContentPath -Force -ErrorAction Stop;
        }
            
    
        # Force a sync for the replication group
        Sync-DfsReplicationGroup -GroupName $using:ReplicationGroupDetails.Name -SourceComputerName $using:ReplicationGroupDetails.Members[0] -DestinationComputerName $using:ReplicationGroupDetails.Members[1] -DurationInMinutes 15;
        Complete-Transaction;
    }
    catch 
    {
        Write-Error "Could not setup DFS replication: $_";
        Undo-Transaction;
    }
}
# .\Undo_DFSR_Changes.ps1 -Session $PrimaryDomainControllerSession -GroupName $using:ReplicationGroupDetails.Name;