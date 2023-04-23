# Description: Main script for executing the post-installation tasks
$TargetSession = New-PSSession -ComputerName (Read-Host "Enter the name or IP ot the server") -Credential (Get-Credential)
$RemotePath = "C:\temp\" # Set the remote path

# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList "C:\temp"))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList "C:\temp";
}

# Copy the script to the remote server
Copy-Item -ToSession $TargetSession -Path "D:\Powershell\Windows_OS_Scripting\Post-installation-tasks\Post-Installation_WindowsServer.ps1" -Destination "c:\temp\Post-Installation_WindowsServer.ps1" -Force;
Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Set-Location $using:remotePath # First set the working directory to the remote path
    . ".\Post-Installation_WindowsServer.ps1"; # Then execute the script for loading the functions
    Show-MainMenu # Finally call the main menu
};

# AUTOMATED VERSION WEEK2