param(
    [parameter(Mandatory=$True,ValueFromPipeline=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=1)]
    [System.Management.Automation.Runspaces.PSSession]
    $Session
);


# Remove the DFS Replication group
Remove-DfsReplicationGroup -CimSession $Session -GroupName $GroupName -Force

# Get the members of the DFS Replication group
$Members = Get-DfsrMember -GroupName $GroupName -CimSession $Session

# Remove each member from the DFS Replication group
$Members | ForEach-Object {
    Remove-DfsReplicationMember -GroupName $GroupName -ComputerName $_.ComputerName -Force -CimSession $Session
}