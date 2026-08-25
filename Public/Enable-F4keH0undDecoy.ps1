<#
.SYNOPSIS
    Enables an AD-backed decoy identity and records a lifecycle event.

.DESCRIPTION
    Enables a User or Computer decoy account using Enable-ADAccount, then
    records the lifecycle transition in the persistent inventory backend.

.PARAMETER Identity
    Identity of the decoy object to enable.

.PARAMETER ObjectType
    Type of decoy identity. Supports User and Computer.

.PARAMETER DecoyType
    Decoy classification label used in persistent inventory events.

.PARAMETER Server
    Optional Domain Controller for AD operations.

.PARAMETER Credential
    Optional privileged credential for AD operations.

.PARAMETER PassThru
    Returns the updated AD object.

.EXAMPLE
    Enable-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User
#>
function Enable-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [ValidateSet('User', 'Computer')]
        [string]$ObjectType = 'User',

        [Parameter()]
        [string]$DecoyType = 'LifecycleManagedDecoy',

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $adParams = @{}
        if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

        $getParams = $adParams.Clone()
        $getParams['Identity'] = $Identity
        $getParams['Properties'] = @('Enabled', 'DistinguishedName', 'SamAccountName', 'Name')
        $getParams['ErrorAction'] = 'Stop'

        switch ($ObjectType) {
            'User' { $decoyObject = Get-ADUser @getParams }
            'Computer' { $decoyObject = Get-ADComputer @getParams }
        }

        if ($null -eq $decoyObject) {
            Write-Error "[ERROR] Could not find decoy '$Identity' of type '$ObjectType'."
            return
        }

        $metadata = @{}
        if (-not $decoyObject.Enabled) {
            $target = $decoyObject.DistinguishedName
            $action = 'Enable account'
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                $enableParams = $adParams.Clone()
                $enableParams['Identity'] = $decoyObject
                $enableParams['ErrorAction'] = 'Stop'
                Enable-ADAccount @enableParams
                $metadata['Changed'] = $true
            }
        }
        else {
            Write-Verbose "[$($MyInvocation.MyCommand)] - Decoy '$Identity' is already enabled."
            $metadata['Changed'] = $false
            $metadata['AlreadyEnabled'] = $true
        }

        $refreshParams = $adParams.Clone()
        $refreshParams['Identity'] = $Identity
        $refreshParams['Properties'] = @('Enabled', 'DistinguishedName', 'SamAccountName', 'Name')
        $refreshParams['ErrorAction'] = 'Stop'

        switch ($ObjectType) {
            'User' { $updatedObject = Get-ADUser @refreshParams }
            'Computer' { $updatedObject = Get-ADComputer @refreshParams }
        }

        Write-F4keH0undInventoryEvent -Action 'Enable' -Identity $Identity -DecoyType $DecoyType -Platform 'AD' -ObjectType $ObjectType -Status 'Enabled' -Location $updatedObject.DistinguishedName -Metadata $metadata -SourceCommand $MyInvocation.MyCommand.Name

        Write-Host "[SUCCESS] Decoy '$Identity' is enabled." -ForegroundColor Green

        if ($PassThru) {
            return $updatedObject
        }
    }
}
