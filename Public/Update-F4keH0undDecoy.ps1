<#
.SYNOPSIS
    Updates an existing deceptive element with lifecycle-safe modifications.

.DESCRIPTION
    Applies controlled updates to an existing decoy and records a persistent
    lifecycle inventory event.

    - AD mode supports description, group membership, and SPN updates.
    - Entra mode supports decoy-description updates for service principals,
      guest users, and app registrations.

.PARAMETER Identity
    Identity of the target decoy object.

.PARAMETER Platform
    Decoy platform to manage. Supports AD and Entra.

.PARAMETER ObjectType
    Decoy object type. AD: User/Computer/Group. Entra:
    ServicePrincipal/GuestUser/AppRegistration.

.PARAMETER DecoyType
    Decoy classification label used in persistent inventory events.

.PARAMETER Description
    Optional replacement description.

.PARAMETER AddGroups
    Optional groups to add the decoy object to (AD mode).

.PARAMETER RemoveGroups
    Optional groups to remove the decoy object from (AD mode).

.PARAMETER AddServicePrincipalNames
    Optional SPNs to add (AD User/Computer only).

.PARAMETER RemoveServicePrincipalNames
    Optional SPNs to remove (AD User/Computer only).

.PARAMETER Server
    Optional Domain Controller for AD operations.

.PARAMETER Credential
    Optional privileged credential for AD operations.

.PARAMETER PassThru
    Returns the updated object.

.EXAMPLE
    Update-F4keH0undDecoy -Identity "svc_sql_legacy" -Platform AD -ObjectType User -Description "Legacy SQL service account" -AddGroups "DnsAdmins"

.EXAMPLE
    Update-F4keH0undDecoy -Identity "7bc0cc2d-8b7e-4cde-89be-d5fdca7f9a5f" -Platform Entra -ObjectType ServicePrincipal -Description "Legacy BI Analytics Connector"
#>
function Update-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [ValidateSet('AD', 'Entra')]
        [string]$Platform = 'AD',

        [Parameter()]
        [ValidateSet('User', 'Computer', 'Group', 'ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$ObjectType = 'User',

        [Parameter()]
        [string]$DecoyType = 'LifecycleManagedDecoy',

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [string[]]$AddGroups,

        [Parameter()]
        [string[]]$RemoveGroups,

        [Parameter()]
        [string[]]$AddServicePrincipalNames,

        [Parameter()]
        [string[]]$RemoveServicePrincipalNames,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        if ($Platform -eq 'Entra') {
            if ($ObjectType -notin @('ServicePrincipal', 'GuestUser', 'AppRegistration')) {
                Write-Error "[ERROR] ObjectType '$ObjectType' is not supported in Entra mode. Use ServicePrincipal, GuestUser, or AppRegistration."
                return
            }

            try {
                Test-PrivateEntraLifecyclePrerequisite | Out-Null
                $decoyObject = Resolve-PrivateEntraDecoyObject -Identity $Identity -ObjectType $ObjectType
            }
            catch {
                Write-Error "[ERROR] Failed to resolve Entra decoy '$Identity' ($ObjectType). Error: $($_.Exception.Message)"
                return
            }

            $changeLog = @{}

            if ($PSBoundParameters.ContainsKey('Description')) {
                $target = "$ObjectType '$($decoyObject.DisplayName)'"
                $action = 'Update decoy description metadata'
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        switch ($ObjectType) {
                            'ServicePrincipal' {
                                Update-MgServicePrincipal -ServicePrincipalId $decoyObject.Id -Notes $Description -ErrorAction Stop
                            }
                            'GuestUser' {
                                Update-MgUser -UserId $decoyObject.Id -JobTitle $Description -ErrorAction Stop
                            }
                            'AppRegistration' {
                                Update-MgApplication -ApplicationId $decoyObject.Id -Notes $Description -ErrorAction Stop
                            }
                        }

                        $changeLog['Description'] = "Updated to '$Description'"
                    }
                    catch {
                        Write-Error "[ERROR] Failed to update Entra decoy '$Identity'. Error: $($_.Exception.Message)"
                        return
                    }
                }
            }

            if (@($AddGroups).Count -gt 0 -or @($RemoveGroups).Count -gt 0) {
                Write-Warning "[WARNING] Group membership updates are not implemented for Entra lifecycle updates yet."
                $changeLog['GroupMembershipRequested'] = $true
            }

            if (@($AddServicePrincipalNames).Count -gt 0 -or @($RemoveServicePrincipalNames).Count -gt 0) {
                Write-Warning "[WARNING] SPN updates are AD-only and were ignored for Entra decoys."
                $changeLog['SPNUpdateRequested'] = $true
            }

            if ($changeLog.Count -eq 0) {
                $changeLog['NoChanges'] = $true
            }

            try {
                $updatedObject = Get-PrivateEntraDecoyObjectById -ObjectId $decoyObject.Id -ObjectType $ObjectType
                $eventContext = Get-PrivateEntraDecoyEventContext -ObjectType $ObjectType -Object $updatedObject
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

            Write-F4keH0undInventoryEvent -Action 'Update' -Identity $eventContext.Identity -DecoyType $eventDecoyType -Platform 'Entra' -ObjectType $ObjectType -Status $eventContext.Status -Location $eventContext.Location -Metadata $changeLog -SourceCommand $MyInvocation.MyCommand.Name

            $displayLabel = if ([string]::IsNullOrWhiteSpace($eventContext.DisplayName)) { $eventContext.Identity } else { $eventContext.DisplayName }
            Write-Host "[SUCCESS] Updated Entra decoy '$displayLabel' (Type: $ObjectType)." -ForegroundColor Green

            if ($PassThru) {
                return $updatedObject
            }

            return
        }

        if ($ObjectType -notin @('User', 'Computer', 'Group')) {
            Write-Error "[ERROR] ObjectType '$ObjectType' is not valid in AD mode. Use User, Computer, or Group."
            return
        }

        $adParams = @{}
        if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

        $getParams = $adParams.Clone()
        $getParams['Identity'] = $Identity
        $getParams['ErrorAction'] = 'Stop'

        switch ($ObjectType) {
            'User' {
                $getParams['Properties'] = @('Description', 'Enabled', 'DistinguishedName', 'SamAccountName', 'Name', 'MemberOf', 'ServicePrincipalName')
                $decoyObject = Get-ADUser @getParams
            }
            'Computer' {
                $getParams['Properties'] = @('Description', 'Enabled', 'DistinguishedName', 'SamAccountName', 'Name', 'MemberOf', 'ServicePrincipalName')
                $decoyObject = Get-ADComputer @getParams
            }
            'Group' {
                $getParams['Properties'] = @('Description', 'DistinguishedName', 'Name', 'MemberOf')
                $decoyObject = Get-ADGroup @getParams
            }
        }

        if ($null -eq $decoyObject) {
            Write-Error "[ERROR] Could not find decoy '$Identity' of type '$ObjectType'."
            return
        }

        $changeLog = @{}

        if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $decoyObject.Description) {
            $target = $decoyObject.DistinguishedName
            $action = 'Update description'
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                $setParams = $adParams.Clone()
                $setParams['Identity'] = $decoyObject
                $setParams['Description'] = $Description
                $setParams['ErrorAction'] = 'Stop'

                switch ($ObjectType) {
                    'User' { Set-ADUser @setParams }
                    'Computer' { Set-ADComputer @setParams }
                    'Group' { Set-ADGroup @setParams }
                }

                $changeLog['Description'] = "Updated to '$Description'"
            }
        }

        foreach ($group in @($AddGroups)) {
            if ([string]::IsNullOrWhiteSpace($group)) { continue }

            $target = "Group '$group'"
            $action = "Add member '$($decoyObject.Name)'"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    $addParams = $adParams.Clone()
                    $addParams['Identity'] = $group
                    $addParams['Members'] = $decoyObject
                    $addParams['ErrorAction'] = 'Stop'
                    Add-ADGroupMember @addParams

                    if (-not $changeLog.ContainsKey('GroupsAdded')) { $changeLog['GroupsAdded'] = @() }
                    $changeLog['GroupsAdded'] = @($changeLog['GroupsAdded']) + $group
                }
                catch {
                    Write-Warning "[WARNING] Failed to add '$($decoyObject.Name)' to group '$group'. Error: $($_.Exception.Message)"
                }
            }
        }

        foreach ($group in @($RemoveGroups)) {
            if ([string]::IsNullOrWhiteSpace($group)) { continue }

            $target = "Group '$group'"
            $action = "Remove member '$($decoyObject.Name)'"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    $removeParams = $adParams.Clone()
                    $removeParams['Identity'] = $group
                    $removeParams['Members'] = $decoyObject
                    $removeParams['Confirm'] = $false
                    $removeParams['ErrorAction'] = 'Stop'
                    Remove-ADGroupMember @removeParams

                    if (-not $changeLog.ContainsKey('GroupsRemoved')) { $changeLog['GroupsRemoved'] = @() }
                    $changeLog['GroupsRemoved'] = @($changeLog['GroupsRemoved']) + $group
                }
                catch {
                    Write-Warning "[WARNING] Failed to remove '$($decoyObject.Name)' from group '$group'. Error: $($_.Exception.Message)"
                }
            }
        }

        if ($ObjectType -in @('User', 'Computer')) {
            if (@($AddServicePrincipalNames).Count -gt 0) {
                $target = $decoyObject.DistinguishedName
                $action = 'Add ServicePrincipalName values'
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        $spnAddParams = $adParams.Clone()
                        $spnAddParams['Identity'] = $decoyObject
                        $spnAddParams['Add'] = @{ servicePrincipalName = @($AddServicePrincipalNames) }
                        $spnAddParams['ErrorAction'] = 'Stop'

                        if ($ObjectType -eq 'User') {
                            Set-ADUser @spnAddParams
                        }
                        else {
                            Set-ADComputer @spnAddParams
                        }

                        $changeLog['SPNsAdded'] = @($AddServicePrincipalNames)
                    }
                    catch {
                        Write-Warning "[WARNING] Failed to add SPNs on '$Identity'. Error: $($_.Exception.Message)"
                    }
                }
            }

            if (@($RemoveServicePrincipalNames).Count -gt 0) {
                $target = $decoyObject.DistinguishedName
                $action = 'Remove ServicePrincipalName values'
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        $spnRemoveParams = $adParams.Clone()
                        $spnRemoveParams['Identity'] = $decoyObject
                        $spnRemoveParams['Remove'] = @{ servicePrincipalName = @($RemoveServicePrincipalNames) }
                        $spnRemoveParams['ErrorAction'] = 'Stop'

                        if ($ObjectType -eq 'User') {
                            Set-ADUser @spnRemoveParams
                        }
                        else {
                            Set-ADComputer @spnRemoveParams
                        }

                        $changeLog['SPNsRemoved'] = @($RemoveServicePrincipalNames)
                    }
                    catch {
                        Write-Warning "[WARNING] Failed to remove SPNs on '$Identity'. Error: $($_.Exception.Message)"
                    }
                }
            }
        }
        elseif (@($AddServicePrincipalNames).Count -gt 0 -or @($RemoveServicePrincipalNames).Count -gt 0) {
            Write-Warning '[WARNING] ServicePrincipalName updates are only supported for User/Computer decoys.'
        }

        if ($changeLog.Count -eq 0) {
            $changeLog['NoChanges'] = $true
        }

        $refreshParams = $adParams.Clone()
        $refreshParams['Identity'] = $Identity
        $refreshParams['ErrorAction'] = 'Stop'

        switch ($ObjectType) {
            'User' {
                $refreshParams['Properties'] = @('Description', 'Enabled', 'DistinguishedName', 'SamAccountName', 'Name', 'ServicePrincipalName', 'MemberOf')
                $updatedObject = Get-ADUser @refreshParams
            }
            'Computer' {
                $refreshParams['Properties'] = @('Description', 'Enabled', 'DistinguishedName', 'SamAccountName', 'Name', 'ServicePrincipalName', 'MemberOf')
                $updatedObject = Get-ADComputer @refreshParams
            }
            'Group' {
                $refreshParams['Properties'] = @('Description', 'DistinguishedName', 'Name', 'MemberOf')
                $updatedObject = Get-ADGroup @refreshParams
            }
        }

        $status = if ($ObjectType -eq 'Group') {
            'Present'
        }
        elseif ($updatedObject.Enabled) {
            'Enabled'
        }
        else {
            'Disabled'
        }

        Write-F4keH0undInventoryEvent -Action 'Update' -Identity $Identity -DecoyType $DecoyType -Platform 'AD' -ObjectType $ObjectType -Status $status -Location $updatedObject.DistinguishedName -Metadata $changeLog -SourceCommand $MyInvocation.MyCommand.Name

        Write-Host "[SUCCESS] Updated decoy '$Identity' (Type: $ObjectType)." -ForegroundColor Green

        if ($PassThru) {
            return $updatedObject
        }
    }
}
