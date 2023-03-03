# CHECK IF SCRIPT IS RUNNED WITH ELEVATED PERMISSIONS IF NOT RESTART WITH ELEVATED PERMISSUONS
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($admin -eq $false) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" -ErrorAction Stop; #variable contains information about the current invocation of the script, including the command used to start the script,
    exit;
}

# TO DO: Promotion of the server to a domain controller


# TO DO: Check if necessary roles are installed

# TO DO: Create the first domain controller in the new forest and new windows domain

# TO DO: reboot the server and wait for the server to come back online

# TO DO: Create the reverse lookup zone for the subnet and make sure the pointer record of the first domain controller appears in that zone

# TO DO: Rename the 'default-first-site-name' to a meaningful name and add your subnet to it

# TO DO: Configure as DHCP server - Check if nessary roles are installed
# TO DO: Authorize the DHCP server to serve DHCP requests in the subnet

# TO DO: Remover warning about the DHCP server not being authorized to serve DHCP requests in the subnet

# TO DO: Create IPv4 scope for the subnet (DHCP scope option)

# TO DO: Create the correct DHCP server options