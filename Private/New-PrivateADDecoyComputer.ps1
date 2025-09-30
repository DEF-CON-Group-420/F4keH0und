function New-PrivateADDecoyComputer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    $adParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

    try {
        # Get the default 'Computers' container for the domain
        $domainInfo = Get-ADDomain @adParams
        $computerPath = $domainInfo.ComputersContainer

        Write-Verbose "[$($MyInvocation.MyCommand)] - Creating AD Computer '$Name'."
        
        $computerParams = $adParams.Clone()
        $computerParams['Name'] = $Name
        $computerParams['Path'] = $computerPath
        $computerParams['Description'] = $Description
        $computerParams['Enabled'] = $true # Computers are typically enabled
        $computerParams['PassThru'] = $true
        $computerParams['ErrorAction'] = 'Stop'
        
        $newComputer = New-ADComputer @computerParams

        Write-Verbose "[$($MyInvocation.MyCommand)] - Setting Unconstrained Delegation for '$Name'."
        
        $setParams = $adParams.Clone()
        $setParams['Identity'] = $newComputer
        $setParams['TrustedForDelegation'] = $true

        Set-ADComputer @setParams

        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully created and configured computer '$($newComputer.DistinguishedName)'."
        return $newComputer
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to create AD computer '$Name'. Error: $($_.Exception.Message)"
        return $null
    }
}