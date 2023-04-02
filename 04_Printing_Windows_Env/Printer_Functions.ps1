# TO DO: Make sure the Print and document services are installed.


# change the location of the print spool folder. Make a script to easily change this location.
function Move-SpoolFolder
{
    <#
        .SYNOPSIS
        Move the print spool folder to a new location.

        .DESCRIPTION
        This function moves the print spool folder to a new location. This is useful if the C drive is running out of space. The function also updates the registry to point to the new location.

        .PARAMETER NewSpoolerPath
        The new location of the print spool folder.

        .EXAMPLE
        Move-SpoolFolder -NewSpoolerPath "C:\Spooler"
    #>
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$NewSpoolerPath
    );

    if(-not (Test-Path -Path "$NewSpoolerPath" -PathType Container)) # Check if the new spooler path exists
    {
        New-Item -Path "$NewSpoolerPath" -ItemType Directory -Force; # Create the new spooler path if it doesn't exist
    }

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
}

function Install-PrintDriver # Manually download and extract a printer driver, e.g. the HP Universal printer driver.
{
    <#
        .SYNOPSIS
        Manually download and extract a printer driver, e.g. the HP Universal printer driver.

        .DESCRIPTION
        This function manually downloads and extracts a printer driver, e.g. the HP Universal printer driver. The function also checks if the driver already exists. 
        If the driver already exists, the function will not install the driver again.

        .PARAMETER PrintDriverName
        The name of the printer driver.

        .PARAMETER DownloadPath
        The path where the printer driver will be downloaded to.

        .PARAMETER DownloadUrl
        The URL where the printer driver can be downloaded from.

        .EXAMPLE
        Install-PrintDriver -PrintDriverName "Universal_print_driver-HP.exe" -DownloadPath "C:\Temp" -DownloadUrl "https://ftp.hp.com/pub/softlib/software13/printers/HP_Universal_Print_Driver_PCL6_Full_Solution_v6.6.0.20064.exe"
    #>
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$PrintDriverName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$DownloadPath,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=2)]
        [ValidatePattern("^https?://")] # Check if the URL is valid
        [string]$DownloadUrl
    );

    
    if(-not (Test-Path -Path "$DownloadPath")) # Check if the driver path exists
    {
        New-Item -Path "$DownloadPath" -ItemType Directory -Force; # Create the driver path if it doesn't exist
    }
    
    try 
    {
        Set-Location $DownloadPath; # Change the current directory to the download path
        Invoke-WebRequest -Uri "$DownloadUrl" -OutFile "$PrintDriverName"; # Download the driver from the URL

        if (Test-Archive -Path "$DownloadPath\$PrintDriverName") # If downloaded file is a zip archive, extract it
        {
            Write-Host "Extracting the zip file...";
            $PrintDriverName = Expand-ZipFile -DownloadPath $DownloadPath -PrintDriverName $PrintDriverName; # Get the full path to the driver executable 
        }

        if (-not (Get-PrinterDriver -Name $PrintDriverName -ErrorAction SilentlyContinue)) 
        {
            Start-Process -FilePath $PrintDriverName -ArgumentList "/s /v/qn /l*v $DownloadPath\Install.log" -Wait; # # Install the driver, install silently (/s), without displaying any dialogs, and to create a verbose log file in the specified path and filename (/lv $DownloadPath\Install.log).
        }
        else 
        {
            Write-Warning "The printer driver already exists: $PrintDriverName";
        }
    }
    catch 
    {
        Write-Error "Could not download and extract the printer driver: $_";
    }

    # Check if the driver was installed successfully
    if (Get-PrinterDriver -Name $PrintDriverName -ErrorAction SilentlyContinue) 
    {
        Write-Host "The printer driver $PrintDriverName was installed successfully.";
       
    }
    else 
    {
        Write-Error "The printer driver $PrintDriverName was not installed.";
    }
        
}
# TODO: Let user know what is happening

function Expand-ZipFile
{
    <#
        .SYNOPSIS
        Extract a zip file.

        .DESCRIPTION
        This function extracts a zip file.

        .PARAMETER DownloadPath
        The path where the printer driver will be extracted to.

        .PARAMETER PrintDriverName
        The name of the printer driver.

        .EXAMPLE
        Expand-ZipFile -DownloadPath "C:\Temp" -PrintDriverName "Universal_print_driver-HP.exe"
    #>
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$DownloadPath,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$PrintDriverName
    );
    $ZipPath = Join-Path -Path $DownloadPath -ChildPath $PrintDriverName; # Get the full path to the zip file
    $ExtractPath = Join-Path -Path $DownloadPath -ChildPath ($PrintDriverName -replace '\.zip$',''); # Get the full path to the folder where the zip file will be extracted
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force; # Extract the zip file
    Remove-Item -Path "$DownloadPath\$PrintDriverName" -Force; # Remove the zip file
    return (Get-ChildItem -Path $ExtractPath -Recurse -Filter "*.exe" | Select-Object -First 1 -ExpandProperty FullName); # Get the full path to the driver executable
}

function Test-Archive  # Check if a file is a zip archive, weird gimmick with executable print HP Universal printer driver
{
    <#
        .SYNOPSIS
        Check if a file is a zip archive.

        .DESCRIPTION
        This function checks if a file is a zip archive.

        .PARAMETER Path
        The path to the file.

        .EXAMPLE
        Test-Archive -Path "C:\Temp\Universal_print_driver-HP.exe"
    #>

    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    );
    
    try 
    {
        $FileStream = [System.IO.File]::OpenRead($Path); # Open the file as a stream
        [System.IO.Compression.ZipArchive]::new($FileStream); # Create a new ZipArchive object
        $IsArchive = $true; # Set the IsArchive variable to true
    }
    catch {
        $IsArchive = $false; # Set the IsArchive variable to false if an error occurs
    }
    finally 
    {
        $fileStream.Dispose(); # Close the file stream
    }

    return $isArchive
}







# Install and share a network printer, with IP address 172.23.80.3, with that driver.
function Test-PrinterSettings 
{
    <#
        .SYNOPSIS
        Check if the printer settings are valid.

        .DESCRIPTION
        This function checks if the printer settings are valid.

        .PARAMETER PrinterSettings
        A hashtables with printer settings.

        .EXAMPLE
        Test-PrinterSettings -Printer @{
                Name = "HP color LaserJet 2700"
                DriverName = "HP Universal Print Driver PCL6 (v6.7.0.20071)"
                PortName = "LPT2"
                PortNumber = 9100
                PortProtocol = "TCP"
                IPAddress = ""
                StartTime = "08:00"
                EndTime = "18:00"
            }
        
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$PrinterSettings
    )

    # Check if hash table has correct keys: name, drivername, portname, portnumber, portprotocol, ipaddress, driverpath, sharename, location
    $Keys = @("Name","DriverName","PortName","PortNumber","PortProtocol","IPAddress","DriverPath","ShareName","Location");
    $Keys | ForEach-Object
    {
        if(-not $PrinterSettings.ContainsKey($_))
        {
            Write-Error "The hash table does not contain the key $_";
            return $False;
        }
    }
    return $True;
}

function Test-PoolSettings
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$PoolSettings
    )

    $Keys = @("PoolName","DriverPath","PoolPrinters");
    $Keys | ForEach-Object 
    {
        if(-not $PoolSettings.ContainsKey($_))
        {
            Write-Error "The hash table does not contain the key $_";
            return $False;
        }
    }
    return $True;
}

function Test-PrinterExistence 
{
    <#
        .SYNOPSIS
        Check if a printer exists.

        .DESCRIPTION
        This function checks if a printer exists.

        .PARAMETER PrinterName
        The name of the printer.

        .EXAMPLE
        Test-PrinterExistence -PrinterName "HP color LaserJet 2700"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrinterName
    )

    if (Get-Printer -Name "$PrinterName" -ErrorAction SilentlyContinue) 
    {
        Write-Host "The printer $("$PrinterName") installed" -ForegroundColor Green;
        return $true;
    }
    Write-Host "The printer $("$PrinterName") does not exist" -ForegroundColor Red;
    return $false;
    
}

function New-SharedPrinter
{
    <#
        .SYNOPSIS
        Share a network printer.

        .DESCRIPTION
        This function shares a network printer.

        .PARAMETER PrinterSettings
        A hashtables with printer settings.

        .EXAMPLE
        New-SharedPrinter -PrinterName "HP color LaserJet 2700";
    #>
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$PrinterName # Array of printer settings (printer name, IP address, driver name, share name) type: [hashtable]
    );
    
    # Share the printer with Everyone
    $Acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$("$PrinterName")"; # Get the ACL of the printer
    $Ar = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","Allow"); # Create a new access rule
    $Acl.SetAccessRule($Ar); # Add the access rule to the ACL
    Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$($PrinterName)" $Acl # Set the ACL of the printer
    Set-Printer -Name $("$PrinterName") -Shared $True # Share the printer
}

function Add-NetworkPrinter 
{
    <#
        .SYNOPSIS
        Install and share a network printer.

        .DESCRIPTION
        This function installs and shares a network printer.

        .PARAMETER PrinterSettings
        An array containing hashtables with printer settings.

        .EXAMPLE
        Add-NetworkPrinter -PrinterSeetings @(
            @{
                Name = "HP color LaserJet 2700"
                DriverName = "HP Universal Print Driver PCL6 (v6.7.0.20071)"
                PortName = "LPT2"
                PortNumber = 9100
                PortProtocol = "TCP"
                IPAddress = ""
                StartTime = "08:00"
                EndTime = "18:00"
                ShareName = "HPcolorLaserJet2700"
            }
        );

    #>
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [array]$PrinterSettings # Array of printer settings (printer name, IP address, driver name, share name) type: [hashtable]
    );
    
        
    
    $PrinterSettings | ForEach-Object
    {
        # Check if hash table has correct keys: name, drivername, portname, portnumber, portprotocol, ipaddress, driverpath, sharename, location
        if((Test-PrinterSettings -PrinterSettings $_) -and (-not (Test-PrinterExistence -PrinterSettings $_))) # Check if the printer settings are valid and if the printer exists
        {
            
            if($_.StartTime -and $_.EndTime) # Check if the printer has a start and end time, if so Add-PrinterDriver with the -StartTime and -UntilTime parameters
            {
                Add-Printer -ConnectionName "\\$($_.IPAddress)\$($_.ShareName)" `
                -Name $_.Name `
                -DriverName $_.DriverName `
                -ShareName $_.ShareName `
                -PortName $_.PortName `
                -Location $_.Locationn
                -StartTime $_.StartTime `
                -UntilTime $_.EndTime;
            }
            else # Add the printer without the -StartTime and -UntilTime parameters
            {
                Add-Printer -ConnectionName "\\$($_.IPAddress)\$($_.ShareName)" `
                -Name $_.Name `
                -DriverName $_.DriverName `
                -ShareName $_.ShareName `
                -PortName $_.PortName `
                -Location $_.Locationn;
            }
        
            # Share the printer with Everyone
            New-SharedPrinter -PrinterName $_.Name;
        
            # Check if the printer was installed successfully
            Test-PrinterExistence -PrinterSettings $_;
        }
    }
}

function Remove-UnusedPrinter
{
    <#
        .SYNOPSIS
        Remove a printer and its unused ports.

        .DESCRIPTION
        This function removes a printer and its unused ports.

        .PARAMETER PrinterName
        The name of the printer.

        .EXAMPLE
        Remove-UnusedPrinter -PrinterName "HP color LaserJet 2700"
    #>

    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$PrinterName
    );

    # Check if the printer exists
   
    if (Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue)  # If the printer exists
    {
        Remove-Printer -Name $PrinterName -Force; # Remove the printer

        # Retrieve the printer ports that are not used by any printer
        $UnusedPorts = Get-PrinterPort | Where-Object { $null -eq $_.PrinterName };
        $UnusedPorts | ForEach-Object { Remove-PrinterPort -Name $_.Name -Force }; # Remove the unused printer ports
    }
    else {
        Write-Warning "The printer $PrinterName does not exist";
    }
}

function Add-PrinterPool
{
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$PoolName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [array]$Ports,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=2)]
        [ValidateNotNullOrEmpty()]
        [array]$PrintDriverName
    );

    $ports | ForEach-Object { Add-PrinterPort -Name "IP_$_" -PrinterHostAddress $_ };
    Add-Printer -Name "$PoolName" -DriverName "$PrintDriverName" -PortName "$Ports" -Shared $true
    
}



