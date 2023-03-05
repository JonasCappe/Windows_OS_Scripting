
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
        [string[]]$PrefixLength=24


    )

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
        [string]$InterfaceAlias
    )


    $IpAddress = Get-NetIPAddress -InterfaceAlias $InterfaceAlias | Where-Object {$_.AddressFamily -eq "IPv4"}
    
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
        [string]$InterfaceAlias
    )
    $ipAddress = Get-NetIPAddress -InterfaceAlias $InterfaceAlias | Where-Object {$_.AddressFamily -eq "IPv4"};
    return (Out-NetworkIpAddress -IpAddress $ipAddress.IPAddress -SubnetMask $ipAddress.SubnetMask)/$ipAddress.PrefixLength;
}

function Get-BroadcastAddress # Retrieve the broadcast address of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$InterfaceAlias
    )
    $IpAddress = Get-NetIPAddress -InterfaceAlias $InterfaceAlias | Where-Object {$_.AddressFamily -eq "IPv4"};
    $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $IpAddress.PrefixLength;
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -SubnetMask $SubnetMask;
    return ([IpAddress]$NetworkAddress).IPAddress -bor -bnot ([IpAddress]$SubnetMask).IPAddress;
}

function Get-FirstAddressRange # Retrieve the first address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$InterfaceAlias
    )
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -SubnetMask $SubnetMask; # Retrieve the network address of the interface
    return ([IpAddress]($NetworkAddress + 1)).IPAddress # Return the first address of the range of usable addresses
}

function Get-LastAddressRange # Retrieve the last address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$InterfaceAlias
    )
    $BroadcastAddress = Get-BroadcastAddress -InterfaceAlias $InterfaceAlias; # Retrieve the broadcast address of the interface
    return ([IpAddress]($BroadcastAddress - 1)).IPAddress # Return the last address of the range of usable addresses
}