<#
.SYNOPSIS
    Disables a decoy identity and records a lifecycle event.

.DESCRIPTION
    Supports disabling AD and Entra identity decoys.

    - AD mode: disables User/Computer via Disable-ADAccount.
    - Entra mode: disables ServicePrincipal/GuestUser via Microsoft Graph.

.PARAMETER Identity
    Identity of the decoy object to disable.

.PARAMETER Platform
    Decoy platform to manage. Supports AD and Entra.

.PARAMETER ObjectType
    Decoy object type.
    AD: User, Computer.
    Entra: ServicePrincipal, GuestUser.

.PARAMETER DecoyType
    Decoy classification label used in persistent inventory events.

.PARAMETER Server
    Optional Domain Controller for AD operations.

.PARAMETER Credential
    Optional privileged credential for AD operations.

.PARAMETER PassThru
    Returns the updated object.

.EXAMPLE
    Disable-F4keH0undDecoy -Identity "svc_sql_legacy" -Platform AD -ObjectType User

.EXAMPLE
    Disable-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal
#>
function Disable-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [ValidateSet('AD', 'Entra')]
        [string]$Platform = 'AD',

        [Parameter()]
        [ValidateSet('User', 'Computer', 'ServicePrincipal', 'GuestUser')]
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
        if ($Platform -eq 'Entra') {
            if ($ObjectType -notin @('ServicePrincipal', 'GuestUser')) {
                Write-Error "[ERROR] ObjectType '$ObjectType' is not supported in Entra disable mode. Use ServicePrincipal or GuestUser."
                return
            }

            try {
                Test-PrivateEntraLifecyclePrerequisite | Out-Null
                $decoyObject = Resolve-PrivateEntraDecoyObject -Identity $Identity -ObjectType $ObjectType
                $eventContext = Get-PrivateEntraDecoyEventContext -ObjectType $ObjectType -Object $decoyObject
            }
            catch {
                Write-Error "[ERROR] Failed to resolve Entra decoy '$Identity' ($ObjectType). Error: $($_.Exception.Message)"
                return
            }

            $metadata = @{}
            if ($decoyObject.AccountEnabled -eq $true) {
                $target = $eventContext.Location
                $action = 'Disable account'
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        switch ($ObjectType) {
                            'ServicePrincipal' {
                                Update-MgServicePrincipal -ServicePrincipalId $decoyObject.Id -AccountEnabled:$false -ErrorAction Stop
                            }
                            'GuestUser' {
                                Update-MgUser -UserId $decoyObject.Id -AccountEnabled:$false -ErrorAction Stop
                            }
                        }
                        $metadata['Changed'] = $true
                    }
                    catch {
                        Write-Error "[ERROR] Failed to disable Entra decoy '$Identity'. Error: $($_.Exception.Message)"
                        return
                    }
                }
            }
            else {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Entra decoy '$Identity' is already disabled."
                $metadata['Changed'] = $false
                $metadata['AlreadyDisabled'] = $true
            }

            try {
                $updatedObject = Get-PrivateEntraDecoyObjectById -ObjectId $decoyObject.Id -ObjectType $ObjectType
                $updatedContext = Get-PrivateEntraDecoyEventContext -ObjectType $ObjectType -Object $updatedObject
            }
            catch {
                Write-Error "[ERROR] Failed to refresh Entra decoy '$Identity'. Error: $($_.Exception.Message)"
                return
            }

            $eventDecoyType = if ($DecoyType -eq 'LifecycleManagedDecoy') {
                Get-PrivateEntraDecoyTypeLabel -ObjectType $ObjectType
            }
            else {
                $DecoyType
            }

            Write-F4keH0undInventoryEvent -Action 'Disable' -Identity $updatedContext.Identity -DecoyType $eventDecoyType -Platform 'Entra' -ObjectType $ObjectType -Status $updatedContext.Status -Location $updatedContext.Location -Metadata $metadata -SourceCommand $MyInvocation.MyCommand.Name

            $displayLabel = if ([string]::IsNullOrWhiteSpace($updatedContext.DisplayName)) { $updatedContext.Identity } else { $updatedContext.DisplayName }
            Write-Host "[SUCCESS] Entra decoy '$displayLabel' is $($updatedContext.Status.ToLower())." -ForegroundColor Green

            if ($PassThru) {
                return $updatedObject
            }

            return
        }

        if ($ObjectType -notin @('User', 'Computer')) {
            Write-Error "[ERROR] ObjectType '$ObjectType' is not supported in AD disable mode. Use User or Computer."
            return
        }

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
        if ($decoyObject.Enabled) {
            $target = $decoyObject.DistinguishedName
            $action = 'Disable account'
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                $disableParams = $adParams.Clone()
                $disableParams['Identity'] = $decoyObject
                $disableParams['ErrorAction'] = 'Stop'
                Disable-ADAccount @disableParams
                $metadata['Changed'] = $true
            }
        }
        else {
            Write-Verbose "[$($MyInvocation.MyCommand)] - Decoy '$Identity' is already disabled."
            $metadata['Changed'] = $false
            $metadata['AlreadyDisabled'] = $true
        }

        $refreshParams = $adParams.Clone()
        $refreshParams['Identity'] = $Identity
        $refreshParams['Properties'] = @('Enabled', 'DistinguishedName', 'SamAccountName', 'Name')
        $refreshParams['ErrorAction'] = 'Stop'

        switch ($ObjectType) {
            'User' { $updatedObject = Get-ADUser @refreshParams }
            'Computer' { $updatedObject = Get-ADComputer @refreshParams }
        }

        $status = if ($updatedObject.Enabled) { 'Enabled' } else { 'Disabled' }

        Write-F4keH0undInventoryEvent -Action 'Disable' -Identity $Identity -DecoyType $DecoyType -Platform 'AD' -ObjectType $ObjectType -Status $status -Location $updatedObject.DistinguishedName -Metadata $metadata -SourceCommand $MyInvocation.MyCommand.Name

        Write-Host "[SUCCESS] Decoy '$Identity' is $($status.ToLower())." -ForegroundColor Green

        if ($PassThru) {
            return $updatedObject
        }
    }
}
