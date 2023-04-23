function Add-Roles
{
    <#
        .SYNOPSIS
        install the necessary roles

        .DESCRIPTION
        installs the necessary roles if they are not already installed

        .PARAMETER Roles
        The roles to install 

        .EXAMPLE
        Add-Roles -Roles @("DNS","DHCP")
    #>
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Roles
    );
    foreach ($Role in $Roles) 
    {
        if ((Get-WindowsFeature -Name $Role).Installed -eq $False) # Check if necessary roles are installed
        {
            Write-host "Installing $Role..."   
            Install-WindowsFeature -Credential (Get-Credential) -Name $Role -IncludeManagementTools
            Write-Host "$Role installed"
        }
        else
        {
            Write-Host "$Role already installed"
        }
    }
}

$PrimaryDomainControllerSession = New-PSSession -ComputerName $PrimaryDomainController -Credential  (Get-Credential -Message "Enter credentials for $PrimaryDomainController" -UserName "Administrator");

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    # Install the necessary roles
    Add-Roles -Roles @("Adcs-Cert-Authority","NPAS");

    Install-AdcsNetworkPolicyServer
    # Install and configure the root CA
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
    -CACommonName "MCTRootCA" ` # The name of the CA
    -CADistinguishedName "CN=MCTRootCA,DC=intranet,DC=mct,DC=be" ` # The distinguished name of the CA
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" ` # The name of the cryptographic provider
    -KeyLength 4098 ` # The length of the key
    -HashAlgorithmName "AES-256" ` # The hash algorithm
    -ValidityPeriod Years ` # The validity period
    -ValidityPeriodUnits 10; # The number of validity period units

    

    # Create self-signed certificate with validity period of 10 years
    New-SelfSignedCertificate -DnsName "intranet.mct.be"; # this creates a self-signed certificate with the name "intranet.mct.be" and a validity period of 10 years (default)

    #Export and import complete NPS configuration
    # Export-NpsConfiguration -Path "C:\NPSConfig.xml"
    # Import-NpsConfiguration -Path "C:\NPSConfig.xml"

    $Rule = Get-NetFirewallRule | Where-Object {$_.DisplayName -eq "Routing and Remote Access (NP-In)"}
    if ($Rule.Enabled -and ($Rule.Action -eq "Allow") -and (Rule.Protocol -eq "UDP") -and ($Rule.LocalPort -eq "1812,1813")) 
    {
        Write-Output "Firewall rules for incoming Radius traffic are configured correctly."
    } else 
    {
        Write-Output "Firewall rules for incoming Radius traffic are not configured correctly."
        Write-Output "Configuring firewall rules for incoming Radius traffic."
        New-NetFirewallRule -DisplayName "Routing and Remote Access (NP-In)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 1812,1813 -Enabled True
    }


}

# https://learn.microsoft.com/en-us/powershell/module/adcsdeployment/install-adcscertificationauthority?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/nps/export-npsconfiguration?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/nps/import-npsconfiguration?view=windowsserver2022-ps
