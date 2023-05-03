$Credential = (Get-Credential -Message "Enter credentials for $PrimaryDomainController" -UserName "Administrator");
$PrimaryDomainControllerSession = New-PSSession -ComputerName $PrimaryDomainController -Credential $Credential;

Invoke-Command -Session $PrimaryDomainControllerSession -ScriptBlock {
    
 
    # Install the necessary roles
    foreach ($Role in @("Adcs-Cert-Authority","NPAS")) 
    {
        if ((Get-WindowsFeature -Name $Role).Installed -eq $False) # Check if necessary roles are installed
        {
            Write-host "Installing $Role..."   
            Install-WindowsFeature -Credential $using:Credential -Name $Role -IncludeManagementTools
            Write-Host "$Role installed"
        }
        else
        {
            Write-Host "$Role already installed"
        }
    }

   $Identity="RAS and IAS Servers"
    $Members=Get-ADComputer -identity $env:COMPUTERNAME

    try 
    {
        Add-ADGroupMember -Identity $Identity -Members $Members
        Write-Output "Adding $Members to $Identity ..."
    } catch 
    {
        Write-Output "The NPS server $Members is already member of $Identity ..."
    }

    try 
    {
    
        # Install and configure the root CA
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
        -CACommonName "MCTRootCA" ` # The name of the CA
        -CADistinguishedName "CN=MCTRootCA,DC=intranet,DC=mct,DC=be" ` # The distinguished name of the CA
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" ` # The name of the cryptographic provider
        -KeyLength 4098 ` # The length of the key
        -HashAlgorithmName "AES-256" ` # The hash algorithm
        -ValidityPeriod Years ` # The validity period
        -ValidityPeriodUnits 10; # The number of validity period units
    }
    catch
    {
        Write-Output "The CA server is already configured  ..."
    }

    


    # Create self-signed certificate with validity period of 10 years
    New-SelfSignedCertificate -DnsName "intranet.mct.be"; # this creates a self-signed certificate with the name "intranet.mct.be" and a validity period of 10 years (default)

    #Export and import complete NPS configuration
    # Export-NpsConfiguration -Path "C:\NPSConfig.xml"
    # Import-NpsConfiguration -Path "C:\NPSConfig.xml"

    $Rule = Get-NetFirewallRule | Where-Object {$_.DisplayName -eq "Routing and Remote Access (NP-In)"}
    if ($Rule.Enabled -and ($Rule.Action -eq "Allow") -and ($Rule.Protocol -eq "UDP") -and ($Rule.LocalPort -eq "1812,1813")) 
    {
        Write-Output "Firewall rules for incoming Radius traffic are configured correctly."
    } else 
    {
        Write-Output "Firewall rules for incoming Radius traffic are not configured correctly."
        Write-Output "Configuring firewall rules for incoming Radius traffic."
        New-NetFirewallRule -DisplayName "Routing and Remote Access (NP-In)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 1812,1813 -Enabled True
    }

    try 
    {
        $File=".\Radiusclients.csv"
        $RadiusClients=Import-Csv $File -Delimiter ";" -ErrorAction Stop
        Foreach ($RadiusClient in $RadiusClients)
        { 
	        $IP=$RadiusClient.IP
	        $Name=$RadiusClient.Name
	        $Secret=$RadiusClient.Secret

            try 
            {
                New-NpsRadiusClient -Address $IP -Name $Name -SharedSecret $Secret | Out-Null
                Write-Host "Creating RADIUS Client $Name with IP address $IP and secret $Secret ..."
            } 
            catch 
            {
                Write-Host "RADIUS Client $Name with IP address $IP and secret $Secret already exists ..."
            }
        }
    }
    catch 
    {
        Write-Host "Unable to open the file $File ... " -Foreground Red
    }



}

# https://learn.microsoft.com/en-us/powershell/module/adcsdeployment/install-adcscertificationauthority?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/nps/export-npsconfiguration?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/nps/import-npsconfiguration?view=windowsserver2022-ps
