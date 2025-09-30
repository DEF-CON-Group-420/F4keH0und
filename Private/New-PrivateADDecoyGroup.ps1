function New-PrivateADDecoyGroup {
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
        Write-Verbose "[$($MyInvocation.MyCommand)] - Creating AD Group '$Name'."
        $groupParams = $adParams.Clone()
        $groupParams['Name'] = $Name
        $groupParams['SamAccountName'] = $Name
        $groupParams['GroupCategory'] = 'Security'
        $groupParams['GroupScope'] = 'Global'
        $groupParams['Description'] = $Description
        $groupParams['PassThru'] = $true
        $groupParams['ErrorAction'] = 'Stop'

        $newGroup = New-ADGroup @groupParams
        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully created group '$($newGroup.DistinguishedName)'."
        return $newGroup
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to create AD group '$Name'. Error: $($_.Exception.Message)"
        return $null
    }
}