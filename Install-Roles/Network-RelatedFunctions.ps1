
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
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
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
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$InterfaceAlias
    )


    $ipAddress = Get-NetIPAddress -InterfaceAlias $InterfaceAlias | Where-Object {$_.AddressFamily -eq "IPv4"}
    
    $subnetMask = Convert-PrefixToSubnetMask -PrefixLength $ipAddress.PrefixLength # Convert the prefix length to a subnet mask
    $octets = $ipAddress.IPAddress.Split(".") # Split the IP address and subnet mask into octets
    $subnetOctets = $subnetMask.Split(".") # Split the IP address and subnet mask into octets
    $networkOctets = @() # Initialize the network octets array
    
    for ($i = 0; $i -lt $subnetOctets.Length; $i++) {
        $networkOctets += [int]($octets[$i] -band $subnetOctets[$i]) # bitwise AND the IP address byte with the subnet mask byte
    }
    
    $networkOctets = $networkOctets[0..($ipAddress.PrefixLength/8 - 1)] # Remove the octets that are not part of the network address, 8 bits per octet minus the 1st octet (which is always 255)
    [array]::Reverse($networkOctets) # Reverse the array
    $zoneName = $networkOctets -join "." # Join the octets together with a period and return the result
    return $zoneName + ".in-addr.arpa" # Add the in-addr.arpa suffix and return the result
}