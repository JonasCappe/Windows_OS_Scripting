
function Out-NetworkIpAddress # Function to get the network part of an IP address - Took inpiration from bitoperations Sensor & Interfacing
{
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IpAddress,
        [parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$SubnetMask,
        [parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [int]$PrefixLength=24
    );

    if($null -ne $PrefixLength)
    {
        $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $ipconfig.PrefixLength;
    }

    $IpBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes() # returns an array of bytes representing the IP address
    $MaskBytes = [System.Net.IPAddress]::Parse($subNetMask).GetAddressBytes() # returns an array of bytes representing the subnet mask

    $NetworkBytes = for($i = 0; $i -lt $IpBytes.Length; $i++) # for each byte in the IP address
    {
        $IpBytes[$i] -band $MaskBytes[$i] # bitwise AND the IP address byte with the subnet mask byte
    }

    return ([System.Net.IPAddress]::new($NetworkBytes)).ToString() # convert the array of bytes to an IP address and return it as a string
}


# Only created this functions to play arround with network calculations
function Get-NetworkPrefixLength {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [string]$SubnetMask
    )

    $MaskBytes = $SubnetMask.Split('.') | ForEach-Object { [byte]$_ } # Convert each octet to a byte
    $PrefixLength = 0 # Initialize the prefix length

    foreach ($byte in $maskBytes) {
        $prefixLength += [convert]::ToString($byte, 2).Replace('0','').Length # Convert each byte to binary and count the number of 1's
    }

    return $prefixLength
}

function Convert-PrefixToSubnetMask { # Function to convert a prefix length to a subnet mask
    param(
        [Parameter(Mandatory=$true)]
        [int]$PrefixLength
    )

    $BinaryMask = '1' * $PrefixLength + '0' * (32 - $PrefixLength) # Create a binary string of 1's and 0's
    $MaskBytes = for($i=0; $i -lt 4; $i++) { [convert]::ToInt32($binaryMask.Substring($i*8, 8), 2) } # Split the binary string into 4 octets and convert each octet to a byte
    return $MaskBytes -join '.'; # Join the bytes together with a period and return the result
}


function Get-ReverseLookupZoneName # Function to get the reverse lookup zone name for an IP address
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )


    $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"}
    
    $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $IpAddress.PrefixLength # Convert the prefix length to a subnet mask
    $Octets = $IpAddress.IPAddress.Split(".") # Split the IP address and subnet mask into octets
    $SubnetOctets = $SubnetMask.Split(".") # Split the IP address and subnet mask into octets
    $NetworkOctets = @() # Initialize the network octets array
    
    for ($i = 0; $i -lt $SubnetOctets.Length; $i++) {
        $NetworkOctets += [int]($Octets[$i] -band $SubnetOctets[$i]) # bitwise AND the IP address byte with the subnet mask byte
    }
    
    $NetworkOctets = $NetworkOctets[0..($ipAddress.PrefixLength/8 - 1)] # Remove the octets that are not part of the network address, 8 bits per octet minus the 1st octet (which is always 255)
    [array]::Reverse($NetworkOctets) # Reverse the array
    $ZoneName = $NetworkOctets -join "." # Join the octets together with a period and return the result
    return $ZoneName + ".in-addr.arpa" # Add the in-addr.arpa suffix and return the result
}

function Get-ComputerFQDN # Function to get the fully qualified domain name of the computer
{
    $DNSHostName = (Get-WmiObject win32_computersystem).DNSHostName;
    $Domain = (Get-WmiObject win32_computersystem).Domain;
    return "$DNSHostName.$Domain";
}

function Get-Subnet # Retrieve the subnet of an interface (IP address and prefix length, format: x.x.x.x/x)
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $ipAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"};
    return ""+(Out-NetworkIpAddress -IpAddress $ipAddress.IPAddress -SubnetMask (Convert-PrefixToSubnetMask -PrefixLength $ipconfig.PrefixLength))+"/"+$ipAddress.PrefixLength;
}

function Get-BroadcastAddress # Retrieve the broadcast address of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"};
    $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $IpAddress.PrefixLength;
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -SubnetMask $SubnetMask;
    return ([IpAddress]$NetworkAddress).IPAddress -bor -bnot ([IpAddress]$SubnetMask).IPAddress;
}

function Get-FirstAddressRange # Retrieve the first address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -SubnetMask $SubnetMask; # Retrieve the network address of the interface
    return ([IpAddress]($NetworkAddress + 1)).IPAddress # Return the first address of the range of usable addresses
}

function Get-LastAddressRange # Retrieve the last address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $BroadcastAddress = Get-BroadcastAddress -InterfaceIndex $InterfaceIndex; # Retrieve the broadcast address of the interface
    return ([IpAddress]($BroadcastAddress - 1)).IPAddress # Return the last address of the range of usable addresses
}

function Get-AddressInSubnet
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$IpAddress,
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$SubnetMask,
        [parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [int]$Place
    );

    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress -SubnetMask $SubnetMask; # Retrieve the network address
    return ([IpAddress]($NetworkAddress + $Place)).IPAddress; # Return the address at the specified place   
}

# TO DO: CHECK IF PROMOTED TO DC WIT WMI OBJECT
function Show-PromotionInProgress
{
    if((Get-WmiObject Win32_NTDomain).DcPromoOperationProgress -eq 1) # Check if the server needs to be promoted to a domain controller 
    {
        Write-Host "Doomain controller promotion in progress" -ForegroundColor Green;
        return $true;
    }
    else
    {
        Write-Host "No domain controller promotion in progress" -ForegroundColor Green;
        return $false;
    }
}
function Get-ADDCRole
{
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain; # Get the domain name
    
    # Check if the server is a domain controller
    if((Get-WmiObject Win32_ComputerSystem).Name -eq(Get-ADDomainController -Discover -Domain $Domain -Service "PrimaryDC" -ErrorAction SilentlyContinue).Name) # Check if the server is a primary domain controller
    {
        return "PrimaryDC";
    }
    elseif((Get-WmiObject Win32_ComputerSystem).Name -eq(Get-ADDomainController -Discover -Domain $Domain -Service "BackupDC" -ErrorAction SilentlyContinue).Name) # Check if the server is a backup domain controller
    {
        return "BackupDC";
    }
    else # The server is a member server
    {
        return "MemberServer";
    }
}

function Get-PrimaryDC
{
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain; # Get the domain name
    return (Get-ADDomainController -Discover -Domain $Domain -Service "PrimaryDC" -ErrorAction SilentlyContinue).Name; # Get the name of the primary domain controller
}