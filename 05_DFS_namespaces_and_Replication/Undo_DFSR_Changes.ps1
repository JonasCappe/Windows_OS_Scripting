param(
    [parameter(Mandatory=$True,ValueFromPipeline=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=1)]
    [System.Management.Automation.Runspaces.PSSession]
    $Session
);


Invoke-Command -Session $Session -ScriptBlock {


    # Remove connection(s)
    Get-DfsrConnection -GroupName $using:GroupName | Remove-DfsrConnection -Force;

    # Remove ReplicatedFolder(s)
    Get-DfsReplicatedFolder -GroupName | Remove-DfsReDfsReplicatedFolder -Force;

    # Get the members of the DFS Replication group
    $Members = Get-DfsrMember -GroupName $using:GroupName;
    
    # Remove each member from the DFS Replication group
    $Members | ForEach-Object {
        Remove-DfsrMember -GroupName $using:GroupName -ComputerName $_.ComputerName -Force;
    }

    # Remove the DFS Replication group
    Remove-DfsReplicationGroup -GroupName $using:GroupName -Force;
    
}