# TO DO: Ensure that you can also calulate the network address from smaller networks (e.g. /25 - /30)
function Out-NetworkIpAddress # Function to calculate the network address of an IP address and subnet mask 
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
        [int]$PrefixLength=0
    );

    if(0 -ne $PrefixLength)
    {
        $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $PrefixLength;
    }

    $IpBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes(); # Convert the IP address to bytes
    $MaskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes(); # Convert the subnet mask to bytes

    $NetworkBytes = for($i = 0; $i -lt $IpBytes.Length; $i++) 
    {
        $IpBytes[$i] -band $MaskBytes[$i];
    }

    return ([System.Net.IPAddress]::new($NetworkBytes)).ToString();
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
    return (Out-NetworkIpAddress -IpAddress $ipAddress.IPAddress -SubnetMask (Convert-PrefixToSubnetMask -PrefixLength $ipAddress.PrefixLength))+"/"+$ipAddress.PrefixLength;
}

function Get-BroadcastAddress # Retrieve the broadcast address of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"}; # Get the IP address config of the interface
    $SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $IpAddress.PrefixLength; # Convert the prefix length to a subnet mask
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -SubnetMask $SubnetMask; # Get the network address of the interface
    $NetworkAddressBytes = [System.Net.IPAddress]::Parse($NetworkAddress).GetAddressBytes();
    
    # Perform a bitwise OR operation on the network address and the inverse of the subnet mask
    $BroadcastAddressBytes = for($i = 0; $i -lt $NetworkAddressBytes.Length; $i++) # Loop through each byte of the network address
    {
        $NetworkAddressBytes[$i] -bor (255 - $SubnetMask.Split('.')[($i)]);
    }

    return ([System.Net.IPAddress]::new($BroadcastAddressBytes)).ToString(); # Convert the broadcast address bytes to an IP address and return the result
}




function Get-FirstAddressRange # Retrieve the first address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"}; # Retrieve the IP address of the interface
   
    $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -PrefixLength $IpAddress.PrefixLength; # Retrieve the network address of the interface
    # Increment the last byte of the network address by 1
    $NetworkAddressBytes = [System.Net.IPAddress]::Parse($NetworkAddress).GetAddressBytes(); # Convert the network address to bytes
    $NetworkAddressBytes[3] += 1; # Increment the last byte of the network address by 1 (the first address of the range of usable addresses)
    return ([System.Net.IPAddress]::new($NetworkAddressBytes)).ToString(); # Convert the network address bytes to an IP address
}

function Get-LastAddressRange # Retrieve the last address of the range of usable addresses of an interface
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex
    )
    $BroadcastAddress = Get-BroadcastAddress -InterfaceIndex $InterfaceIndex; # Retrieve the broadcast address of the interface
    $BroadcastAddressBytes = [System.Net.IPAddress]::Parse($BroadcastAddress).GetAddressBytes(); # Convert the broadcast address to bytes
    $BroadcastAddressBytes[3] -= 1; # Decrement the last byte of the broadcast address by 1 (the last address of the range of usable addresses)
    return ([System.Net.IPAddress]::new($BroadcastAddressBytes)).ToString(); # Convert the broadcast address bytes to an IP address
}
function Get-AddressInSubnet
{
    param(
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [int]$InterfaceIndex,
        [parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [int]$Place=0
    );

    try {
        $IpAddress = Get-NetIPAddress -InterfaceIndex $InterfaceIndex | Where-Object {$_.AddressFamily -eq "IPv4"}; # Retrieve the IP address of the interface
   
        $NetworkAddress = Out-NetworkIpAddress -IpAddress $IpAddress.IPAddress -PrefixLength $IpAddress.PrefixLength; # Retrieve the network address of the interface
        # Increment the last byte of the network address by place
        $NetworkAddressBytes = [System.Net.IPAddress]::Parse($NetworkAddress).GetAddressBytes(); # Convert the network address to bytes
        $NetworkAddressBytes[3] += $Place; # Increment the last byte of the network address by place

        $Result = [System.Net.IPAddress]::new($NetworkAddressBytes).ToString(); # Convert the network address bytes to an IP address

        if($Result -eq (Get-BroadcastAddress -InterfaceIndex $InterfaceIndex)) # Check if is the broadcast address
        {
            Write-Error "Error: This address is the broadcast address, not a usable address";
        }
        elseif($Result -eq (Out-NetworkIpAddress -IpAddress $IpAddress.IpAddress -PrefixLength $IpAddress.PrefixLength)) # Check if is the Network address
        {
            Write-Error "Error: This address is the network address, not a usable address";
        }
        else
        {
            return $Result;
        }
        
       
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)";
    }
   
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