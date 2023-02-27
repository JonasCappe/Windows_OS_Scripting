# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($admin -eq $false) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop #variable contains information about the current invocation of the script, including the command used to start the script,
    exit
}

# ~ CHANGE COMPUTER NAME (with user input) =======================================================================================================================================================================================================================
function ChangeComputerName
{
    Clear-Host
    $newName = Read-Host "Enter new computer name"

    # WITHOUT RESTART OPTION
    Rename-Computer -NewName $newName
    pause
}

# ~ CHECK OF SERVER IS CORE VERSION =======================================================================================================================================================================================================================
function CheckIfServerIsCore
{
    param([string]$OsServer)

    if($OsServer -eq "ServerCore")
    {
        return $true;
    }
    return $false;
}

ChangeComputerName
