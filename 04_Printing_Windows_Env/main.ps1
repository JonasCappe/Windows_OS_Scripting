$RemoteServers = @("192.168.1.3");
$RemotePath = "C:\temp"; # Remote path
$RemoteUser = "intranet\Administrator";
$NewSpoolerPath = "C:\PrintSpooler";
$PrinterSettings = @(
    @{
        Name = "HP Laserjet 4050"
        DriverName = "universal_print_driver-HP.exe"
        PrinterDriver = "HP Universal Printing PCL 6"
        ShareName = "HPLJ4050-KWE.A.2.105"
        IPAddress = "172.23.80.3"
        PortProtocol = "TCP"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
        Location = "KWE.A.2.105"
    }
);

$PrinterSettingsSchedule = @(
    @{
        Name = "HP Laserjet 4050 (DAG)"
        DriverName = "universal_print_driver-HP.exe"
        PrinterDriver = "HP Universal Printing PCL 6"
        ShareName = "HPLJ4050-KWE.A.2.105_DAG"
        IPAddress = "172.23.80.3"
        PortProtocol = "TCP"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
        StartTime = (8-2)*60
        EndTime = (18-2)*60
        Location = "KWE.A.2.105"
    },
    @{
        Name = "HP Laserjet 4050 (Nacht)"
        DriverName = "universal_print_driver-HP.exe"
        PrinterDriver = "HP Universal Printing PCL 6"
        ShareName = "HPLJ4050-KWE.A.2.105_NACHT"
        IPAddress = "172.23.80.3"
        PortProtocol = "TCP"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
        StartTime = (18-2)*60
        EndTime = (8-2)*60
        Location = "KWE.A.2.105"
    }
);

$TargetSession = New-PSSession -ComputerName $RemoteServers[0] -Credential  (Get-Credential -Message "Enter credentials for $($RemoteServers)" -UserName $RemoteUser);
# Check if the destination folder exists remotely, and create it if it doesn't
if (-not (Invoke-Command -Session $TargetSession -ScriptBlock { Test-Path -Path $args[0] } -ArgumentList $RemotePath))
{
    Invoke-Command -Session $TargetSession -ScriptBlock { New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $RemotePath;
}

Copy-Item -ToSession $TargetSession -Path ".\Printer_Functions.ps1" -Destination $RemotePath -Force;

Invoke-Command -Session $TargetSession -ScriptBlock {
    Set-Location $using:RemotePath;
    . ".\Printer_Functions.ps1";
    # Make sure the Print and document services are installed.
    if((Get-WindowsFeature -Name Print-Services).Installed -eq $false) 
    { 
        Install-WindowsFeature -Name Print-Services -IncludeManagementTools; # Install Print Services
    }

    # Change the location of the print spool folder.
    Move-SpoolFolder -NewSpoolerPath $using:NewSpoolerPath;

    # Manually download and extract a printer driver
    $using:PrinterSettings | ForEach-Object {
        Install-PrintDriver -PrintDriverName $_.DriverName -DownloadPath $_.DownloadPath -DownloadUrl $_.DownloadUrl;
    }
    
    # Install and share a network printer, with IP address 172.23.80.3, with that driver.
    Add-NetworkPrinter -PrinterSettings $using:PrinterSettings;
     
    # Remove a printer and its unused printer ports
    Remove-UnusedPrinter -PrinterName $using:PrinterSettings[0].Name;
     
    # Create and share a printer pool with printer ports 172.23.80.3 and 172.23.82.3
    Add-PrinterPool -PoolName "Printer Pool" -Ports @("172.23.80.3", "172.23.82.3") -PrintDriverName "HP Universal Printing PCL 6";
     
    Remove-UnusedPrinter -PrinterName "Printer Pool";
     
    # Create and share a printer that is available from 8am to 6pm, and for nightly prints from 6pm to 8am
    Add-NetworkPrinter -PrinterSettings $using:PrinterSettingsSchedule;
    
    # Reset to always available
    # Set-Printer -Name $using:PrinterSettings[0].Name -StartTime 0 -UntilTime 0;
     

    # # secure a printer (Security-Descriptor) - Script as secondary backdoor with a scheduled task, nonprivileged user has access as system
    # Get-Printer * -full | Select-Object -ExpandProperty PermissionSDDL
    # 
    #$Acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$($Printer.PrinterName)"
 
    #$Acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule("Authenticated users","Print","Allow")));
    
    # Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$($Printer.PrinterName)" $Acl
    # Set-Printer -Name $($Printer.PrinterName) -Shared $True
    
    
}
# TODO: FINSIH SCRIPT SECURING PRINTERS AND ADDING POOL WITH SCHEDULE