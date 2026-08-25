<#
.SYNOPSIS
    Enables a decoy identity and records a lifecycle event.

.DESCRIPTION
    Supports enabling AD and Entra identity decoys.

    - AD mode: enables User/Computer via Enable-ADAccount.
    - Entra mode: enables ServicePrincipal/GuestUser via Microsoft Graph.

.PARAMETER Identity
    Identity of the decoy object to enable.

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
    Enable-F4keH0undDecoy -Identity "svc_sql_legacy" -Platform AD -ObjectType User

.EXAMPLE
    Enable-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal
#>
function Enable-F4keH0undDecoy {
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
                Write-Error "[ERROR] ObjectType '$ObjectType' is not supported in Entra enable mode. Use ServicePrincipal or GuestUser."
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
            if ($decoyObject.AccountEnabled -ne $true) {
                $target = $eventContext.Location
                $action = 'Enable account'
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        switch ($ObjectType) {
                            'ServicePrincipal' {
                                Update-MgServicePrincipal -ServicePrincipalId $decoyObject.Id -AccountEnabled:$true -ErrorAction Stop
                            }
                            'GuestUser' {
                                Update-MgUser -UserId $decoyObject.Id -AccountEnabled:$true -ErrorAction Stop
                            }
                        }
                        $metadata['Changed'] = $true
                    }
                    catch {
                        Write-Error "[ERROR] Failed to enable Entra decoy '$Identity'. Error: $($_.Exception.Message)"
                        return
                    }
                }
            }
            else {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Entra decoy '$Identity' is already enabled."
                $metadata['Changed'] = $false
                $metadata['AlreadyEnabled'] = $true
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

            Write-F4keH0undInventoryEvent -Action 'Enable' -Identity $updatedContext.Identity -DecoyType $eventDecoyType -Platform 'Entra' -ObjectType $ObjectType -Status $updatedContext.Status -Location $updatedContext.Location -Metadata $metadata -SourceCommand $MyInvocation.MyCommand.Name

            $displayLabel = if ([string]::IsNullOrWhiteSpace($updatedContext.DisplayName)) { $updatedContext.Identity } else { $updatedContext.DisplayName }
            Write-Host "[SUCCESS] Entra decoy '$displayLabel' is $($updatedContext.Status.ToLower())." -ForegroundColor Green

            if ($PassThru) {
                return $updatedObject
            }

            return
        }

        if ($ObjectType -notin @('User', 'Computer')) {
            Write-Error "[ERROR] ObjectType '$ObjectType' is not supported in AD enable mode. Use User or Computer."
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

        $status = if ($updatedObject.Enabled) { 'Enabled' } else { 'Disabled' }

        Write-F4keH0undInventoryEvent -Action 'Enable' -Identity $Identity -DecoyType $DecoyType -Platform 'AD' -ObjectType $ObjectType -Status $status -Location $updatedObject.DistinguishedName -Metadata $metadata -SourceCommand $MyInvocation.MyCommand.Name

        Write-Host "[SUCCESS] Decoy '$Identity' is $($status.ToLower())." -ForegroundColor Green

        if ($PassThru) {
            return $updatedObject
        }
    }
}
