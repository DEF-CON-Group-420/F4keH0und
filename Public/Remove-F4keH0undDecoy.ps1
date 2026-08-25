<#
.SYNOPSIS
    Safely removes a decoy object and associated relationships.

.DESCRIPTION
    Removes AD or Entra decoys with safety checks and lifecycle event writes.

    - AD mode removes memberships first, then deletes object.
    - Entra mode removes ServicePrincipal, GuestUser, or AppRegistration decoys.

.PARAMETER Identity
    Identity of the decoy object to remove.

.PARAMETER Platform
    Decoy platform to manage. Supports AD and Entra.

.PARAMETER Server
    Domain Controller for AD operations.

.PARAMETER Credential
    Credentials for AD operations.

.PARAMETER DecoyType
    Object type to remove.
    AD: User, Computer, Group.
    Entra: ServicePrincipal, GuestUser, AppRegistration.

.EXAMPLE
    Remove-F4keH0undDecoy -Identity "decoy_admin" -Platform AD -DecoyType User -WhatIf

.EXAMPLE
    Remove-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -DecoyType ServicePrincipal -WhatIf
#>
function Remove-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [ValidateSet('AD', 'Entra')]
        [string]$Platform = 'AD',

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [Alias('ObjectType')]
        [ValidateSet('User', 'Computer', 'Group', 'ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$DecoyType = 'User'
    )

    process {
        if ($Platform -eq 'Entra') {
            if ($DecoyType -notin @('ServicePrincipal', 'GuestUser', 'AppRegistration')) {
                Write-Error "[ERROR] DecoyType '$DecoyType' is not supported in Entra remove mode. Use ServicePrincipal, GuestUser, or AppRegistration."
                return
            }

            try {
                Test-PrivateEntraLifecyclePrerequisite | Out-Null
                $decoyObject = Resolve-PrivateEntraDecoyObject -Identity $Identity -ObjectType $DecoyType
                $eventContext = Get-PrivateEntraDecoyEventContext -ObjectType $DecoyType -Object $decoyObject
            }
            catch {
                Write-Error "[ERROR] Failed to resolve Entra decoy '$Identity' ($DecoyType). Error: $($_.Exception.Message)"
                return
            }

            $target = $eventContext.Location
            $action = 'Remove Entra decoy object'
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    switch ($DecoyType) {
                        'ServicePrincipal' {
                            Remove-MgServicePrincipal -ServicePrincipalId $decoyObject.Id -ErrorAction Stop
                        }
                        'GuestUser' {
                            Remove-MgUser -UserId $decoyObject.Id -ErrorAction Stop
                        }
                        'AppRegistration' {
                            Remove-MgApplication -ApplicationId $decoyObject.Id -ErrorAction Stop
                        }
                    }

                    $eventMetadata = @{
                        RemovedByCommand = $MyInvocation.MyCommand.Name
                        RemovalMode      = 'Delete'
                        ObjectId         = $decoyObject.Id
                    }

                    $eventDecoyType = Get-PrivateEntraDecoyTypeLabel -ObjectType $DecoyType
                    Write-F4keH0undInventoryEvent -Action 'Remove' -Identity $eventContext.Identity -DecoyType $eventDecoyType -Platform 'Entra' -ObjectType $DecoyType -Status 'Removed' -Location $eventContext.Location -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name

                    $displayLabel = if ([string]::IsNullOrWhiteSpace($eventContext.DisplayName)) { $eventContext.Identity } else { $eventContext.DisplayName }
                    Write-Host "[SUCCESS] Successfully removed Entra decoy '$displayLabel' (Type: $DecoyType)." -ForegroundColor Green
                }
                catch {
                    Write-Error "[ERROR] Failed to remove Entra decoy '$Identity'. Error: $($_.Exception.Message)"
                }
            }

            return
        }

        if ($DecoyType -notin @('User', 'Computer', 'Group')) {
            Write-Error "[ERROR] DecoyType '$DecoyType' is not supported in AD remove mode. Use User, Computer, or Group."
            return
        }

        $adParams = @{}
        if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

        Write-Verbose "[$($MyInvocation.MyCommand)] - Attempting to find decoy '$Identity'."
        $decoyObject = $null
        try {
            $findParams = $adParams.Clone()
            $findParams['Identity'] = $Identity
            $findParams['Properties'] = @('MemberOf', 'DistinguishedName', 'Name')
            $findParams['ErrorAction'] = 'Stop'

            switch ($DecoyType) {
                'User' { $decoyObject = Get-ADUser @findParams }
                'Computer' { $decoyObject = Get-ADComputer @findParams }
                'Group' { $decoyObject = Get-ADGroup @findParams }
            }
        }
        catch {
            Write-Error "[ERROR] Failed to find a decoy with Identity '$Identity' and Type '$DecoyType'. Error: $($_.Exception.Message)"
            return
        }

        if ($null -eq $decoyObject) {
            Write-Error "[ERROR] Could not find a decoy with Identity '$Identity' and Type '$DecoyType'."
            return
        }

        Write-Host "[INFO] Found decoy: $($decoyObject.DistinguishedName)" -ForegroundColor Cyan

        if (@($decoyObject.MemberOf).Count -gt 0) {
            Write-Verbose "[$($MyInvocation.MyCommand)] - Decoy is a member of $($decoyObject.MemberOf.Count) groups. Removing memberships..."
            foreach ($groupDN in $decoyObject.MemberOf) {
                $target = "Group '$groupDN'"
                $action = "Remove member '$($decoyObject.Name)' from"
                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    try {
                        $removeMemberParams = $adParams.Clone()
                        $removeMemberParams['Identity'] = $groupDN
                        $removeMemberParams['Members'] = $decoyObject
                        $removeMemberParams['Confirm'] = $false
                        $removeMemberParams['ErrorAction'] = 'Stop'
                        Remove-ADGroupMember @removeMemberParams
                        Write-Host "[SUCCESS] Removed decoy from group '$groupDN'."
                    }
                    catch {
                        Write-Warning "[WARNING] Failed to remove decoy from group '$groupDN'. Error: $($_.Exception.Message)"
                    }
                }
            }
        }

        $target = $decoyObject.DistinguishedName
        $action = 'Remove Decoy Object'
        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                $removeParams = $adParams.Clone()
                $removeParams['Identity'] = $decoyObject
                $removeParams['Confirm'] = $false
                $removeParams['ErrorAction'] = 'Stop'

                switch ($DecoyType) {
                    'User' { Remove-ADUser @removeParams }
                    'Computer' { Remove-ADComputer @removeParams }
                    'Group' { Remove-ADGroup @removeParams }
                }

                if (Get-Command -Name Write-F4keH0undInventoryEvent -ErrorAction SilentlyContinue) {
                    $eventDecoyType = "$DecoyType`Decoy"
                    $eventMetadata = @{
                        RemovedByCommand = $MyInvocation.MyCommand.Name
                        RemovalMode      = 'Delete'
                    }

                    Write-F4keH0undInventoryEvent -Action 'Remove' -Identity $Identity -DecoyType $eventDecoyType -Platform 'AD' -ObjectType $DecoyType -Status 'Removed' -Location $decoyObject.DistinguishedName -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name
                }

                Write-Host "[SUCCESS] Successfully removed decoy '$($decoyObject.Name)' (Type: $DecoyType)." -ForegroundColor Green
            }
            catch {
                Write-Error "[ERROR] Failed to remove decoy. Error: $($_.Exception.Message)"
            }
        }
    }
}
