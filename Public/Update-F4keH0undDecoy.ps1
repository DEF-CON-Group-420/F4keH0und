<#
.SYNOPSIS
    Updates an existing deceptive element with lifecycle-safe modifications.

.DESCRIPTION
    Applies controlled updates to an existing AD-backed decoy and records a
    persistent lifecycle inventory event. Supports description updates, group
    membership modifications, and SPN changes for user/computer decoys.

.PARAMETER Identity
    Identity of the target decoy object.

.PARAMETER ObjectType
    AD object type of the decoy. Supports User, Computer, and Group.

.PARAMETER DecoyType
    Decoy classification label used in persistent inventory events.

.PARAMETER Description
    Optional replacement description.

.PARAMETER AddGroups
    Optional groups to add the decoy object to.

.PARAMETER RemoveGroups
    Optional groups to remove the decoy object from.

.PARAMETER AddServicePrincipalNames
    Optional SPNs to add (User/Computer only).

.PARAMETER RemoveServicePrincipalNames
    Optional SPNs to remove (User/Computer only).

.PARAMETER Server
    Optional Domain Controller for AD operations.

.PARAMETER Credential
    Optional privileged credential for AD operations.

.PARAMETER PassThru
    Returns the updated AD object.

.EXAMPLE
    Update-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User -Description "Legacy SQL service account" -AddGroups "DnsAdmins"

.EXAMPLE
    Update-F4keH0undDecoy -Identity "WS-LEGACY-07$" -ObjectType Computer -AddServicePrincipalNames "HOST/legacy-app.corp.local"
#>
function Update-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [ValidateSet('User', 'Computer', 'Group')]
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
            $action = "Update description"
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
            Write-Warning "[WARNING] ServicePrincipalName updates are only supported for User/Computer decoys."
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
