<#
    .SYNOPSIS
    Undo the previous changes made to DFS

    .DESCRIPTION
    Undo the previous changes made to DFS

    .PARAMETER Domain
    The domain to use

    .PARAMETER Namespace
    The namespace to use

    .PARAMETER Links
    The links to remove

    .EXAMPLE
    Undo-DfsChanges -Domain "intranet.mct.be" -Namespace "CompanyInfo" -Links @("Recipes","Menus")
#>

param(
    [parameter(Mandatory=$True,ValueFromPipeline=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,
    [parameter(Mandatory=$True,ValueFromPipeline=$True,Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$Namespace,
    [parameter(Mandatory=$True,ValueFromPipeline=$True,Position=2)]
    [ValidateNotNullOrEmpty()]
    [array]$Links,
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=3)]
    [System.Management.Automation.Runspaces.PSSession]
    $Session
);

Invoke-Command -Session $Session -ScriptBlock {
    $using:Links | ForEach-Object {
        Remove-DfsnFolder -Path "\\$($using:Domain)\$($using:NameSpace)\$($_.LinkFolder)" -Force
    }

    # Remove the DFS namespace
    Remove-DfsnRoot -Path "\\$($using:Domain)\$($using:NameSpace)" -Force
}