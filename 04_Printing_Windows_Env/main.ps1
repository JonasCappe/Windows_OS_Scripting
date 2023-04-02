# ~ GLOBAL VARIABLES ====================================================================================================
$RemoteUser = "Administrator"; # User to connect to the remote machine
$Infrastructure = @(
    @{
        Name = "DC1"
        IP = "203.113.11.1"
    }
    @{
        Name = "DC2"
        IP = "203.113.11.2"
    }
    @{
        Name = "MS"
        IP = "203.113.11.3"
    }
); # Remote machines
$PrinterSettings = @(
    @{
        Name = (Read-Host "Enter the name of the printer")
        DriverName = "HP Universal Print Driver PCL6 (v6.7.0.20071)"
        PortName = "LPT2"
        PortNumber = 9100
        PortProtocol = "TCP"
        IPAddress = (Read-Host "Enter the IP address of the printer")
        DriverPath = "$env:TEMP\HPUniversalPrinterDriver.exe"
        ShareName = "HP color LaserJet 2700"
        Locationn = "Office"
        Schedule = @(
            @{
                Name = "Office Hours"
                StartTime = "08:00"
                EndTime = "18:00"
            },
            @{
                Name = "Nightly Prints"
                StartTime = "18:00"
                EndTime = "08:00"
            }
        )
    }
);

$PoolSettings = @(
    @{
        PoolName = "Office Printers"
        Location = "Office"
        DriverPath = "$env:TEMP\HPUniversalPrinterDriver.exe"
        PoolPrinters = @(
            "IP_172.23.80.3"
            "IP_172.23.80.3"
        )
        Schedule = @(
            @{
                Name = "Office Hours"
                StartTime = "08:00"
                EndTime = "18:00"
            },
            @{
                Name = "Nightly Prints"
                StartTime = "18:00"
                EndTime = "08:00"
            }
        )
    }
); # 

$DriverUrl = "http://"

# ~ PrimaryDomainController ==================================================================================================
$TargetSession = New-PSSession -ComputerName $Infrastructure[1].Name -Credential  (Get-Credential -Message "Enter credentials for $($Infrastructure[1].Name)" -UserName $RemoteUser);
$ChangeSpoolFolderScript = ".\Change_Spool_Folder.ps1"; # Path to the script to be executed on the remote machine


Invoke-Command -Session $TargetSession -ScriptBlock { # Execute the script on the remote server
    Install-WindowsFeature -Name Print-Services -IncludeManagementTools; # Install Print Services
    Start-Process $using:ChangeSpoolFolderScript $using:SpoolFolder; # Change the spool folder

    # Install the printer driver
    Install-PrintDriver -DriverName $PrinterSettings[0].DriverName `
    -DriverPath $PrinterSettings[0].DriverFilePath `
    -DriverUrl $DriverUrl; # Install the printer driver

    Add-NetworkPrinter -PrinterSettings $PrinterSettings; # Add the printer

    Remove-UnusedPrinter -PrinterName $PrinterSettings.Name; # Remove the printer

    Add-PrinterPool -PoolSettings $PoolSettings; # Add the printer pool

    Remove-PrinterPool -PoolName $PoolSettings.PoolName; # Remove the printer pool

    .\Printer-Availability.ps1 -PrinterSchedul $PoolSettings.Schedule; # Check the printer availability
}

