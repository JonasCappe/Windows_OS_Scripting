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

Install-PrintDriver -PrintDriverName "universal_print_driver-HP.exe" -DownloadPath "C:\Temp\PrintDrivers" -DownloadUrl "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-24/upd-pcl6-x64-7.0.1.24923.exe";