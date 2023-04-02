param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$NewSpoolerPath
);


Start-Transaction # Start transaction to undo changes if something goes wrong
try 
{
    # Check if the spooler service is running
    if ((Get-Service -Name Spooler).Status -eq "Running")
    {
        Write-Warning "The spooler service is running. Stopping the service now.";
        Stop-Service -Name Spooler # Stop the Spooler service
    }
    Move-Item -Path "C:\Windows\System32\spool\" -Destination $NewSpoolerPath -Force # Move the spool folder to the new location

    # Update the registry to point to the new location
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers" -Name "SpoolDirectory" -Value $NewSpoolerPath
    Start-Service -Name Spooler # Start the Spooler service

    Complete-Transaction
}
catch
{
    Write-Error "Could not change location of the spool folder at this moment: $_";
    Undo-Transaction;
}