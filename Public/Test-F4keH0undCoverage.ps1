<#
.SYNOPSIS
    Computes AD/Entra deception coverage and lifecycle parity status.

.DESCRIPTION
    Builds a normalized coverage matrix from the current inventory and compares
    active AD deception families to Entra equivalents using a parity model.

    The command reports:
    - lifecycle capability coverage by platform,
    - active deployed counts by decoy type,
    - family-level parity gaps (`AD` baseline vs `Entra`), and
    - optional opportunity availability from BloodHound/AzureHound analysis.

.PARAMETER Source
    Inventory source used by Get-F4keH0undInventory.

.PARAMETER IncludeRemoved
    Includes removed lifecycle entries when using events source.

.PARAMETER PreferSnapshot
    Prefer snapshot cache before event-log replay for events source.

.PARAMETER SkipLiveStatus
    Skips live AD status checks and uses recorded inventory state only.

.PARAMETER Server
    Optional Domain Controller for AD live status checks.

.PARAMETER Credential
    Optional credential for AD live status checks.

.PARAMETER TargetParityRatio
    Required Entra-to-AD family ratio to consider parity met. `1.0` means
    equal active Entra and AD coverage per family.

.PARAMETER BloodHoundPath
    Optional AD collector data path used to count current AD opportunities.

.PARAMETER AzureHoundPath
    Optional Entra collector data path used to count current Entra opportunities.

.EXAMPLE
    Test-F4keH0undCoverage -Source Events -PreferSnapshot -SkipLiveStatus

.EXAMPLE
    Test-F4keH0undCoverage -TargetParityRatio 1.0 -AzureHoundPath ./AzureHound_Data
#>
function Test-F4keH0undCoverage {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter()]
        [ValidateSet('Auto', 'Events', 'Reports')]
        [string]$Source = 'Auto',

        [Parameter()]
        [switch]$IncludeRemoved,

        [Parameter()]
        [switch]$PreferSnapshot,

        [Parameter()]
        [switch]$SkipLiveStatus,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(0, 10)]
        [double]$TargetParityRatio = 1.0,

        [Parameter()]
        [string]$BloodHoundPath,

        [Parameter()]
        [string]$AzureHoundPath
    )

    $parityModel = Get-F4keH0undParityModel

    $inventoryParams = @{
        Source = $Source
    }
    if ($IncludeRemoved) { $inventoryParams['IncludeRemoved'] = $true }
    if ($PreferSnapshot) { $inventoryParams['PreferSnapshot'] = $true }
    if ($SkipLiveStatus) { $inventoryParams['SkipLiveStatus'] = $true }
    if ($PSBoundParameters.ContainsKey('Server')) { $inventoryParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $inventoryParams['Credential'] = $Credential }

    $inventoryRows = @()
    try {
        $inventoryRows = @(Get-F4keH0undInventory @inventoryParams)
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to read inventory. Coverage will continue with an empty inventory state. Error: $($_.Exception.Message)"
        $inventoryRows = @()
    }

    $activeRows = @(
        $inventoryRows | Where-Object {
            $_.IsActive -ne $false -and
            [string]$_.Status -ne 'Removed'
        }
    )

    $opportunityCounts = @{}
    if ($PSBoundParameters.ContainsKey('BloodHoundPath')) {
        try {
            $adOpportunities = @(Find-F4keH0undOpportunity -BloodHoundPath $BloodHoundPath -ErrorAction Stop)
            foreach ($bucket in ($adOpportunities | Group-Object -Property DecoyType)) {
                $opportunityCounts[[string]$bucket.Name] = [int]$bucket.Count
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - AD opportunity scan failed for coverage context. Error: $($_.Exception.Message)"
        }
    }

    if ($PSBoundParameters.ContainsKey('AzureHoundPath')) {
        try {
            $entraOpportunities = @(Find-F4keH0undOpportunity -AzureHoundPath $AzureHoundPath -ErrorAction Stop)
            foreach ($bucket in ($entraOpportunities | Group-Object -Property DecoyType)) {
                $existingCount = if ($opportunityCounts.ContainsKey([string]$bucket.Name)) {
                    [int]$opportunityCounts[[string]$bucket.Name]
                }
                else {
                    0
                }
                $opportunityCounts[[string]$bucket.Name] = $existingCount + [int]$bucket.Count
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Entra opportunity scan failed for coverage context. Error: $($_.Exception.Message)"
        }
    }

    $coverageMatrix = foreach ($decoyTypeDef in $parityModel.DecoyTypes) {
        $rowsForType = @(
            $inventoryRows | Where-Object {
                [string]$_.Platform -eq $decoyTypeDef.Platform -and
                [string]$_.DecoyType -eq $decoyTypeDef.DecoyType
            }
        )

        $activeForType = @(
            $rowsForType | Where-Object {
                $_.IsActive -ne $false -and
                [string]$_.Status -ne 'Removed'
            }
        )

        $removedForType = @(
            $rowsForType | Where-Object {
                $_.IsActive -eq $false -or
                [string]$_.Status -eq 'Removed'
            }
        )

        $lastUpdated = $null
        foreach ($row in $rowsForType) {
            $candidateTime = $null
            if ($row.LastUpdated) {
                try {
                    $candidateTime = [datetime]$row.LastUpdated
                }
                catch {
                    $candidateTime = $null
                }
            }
            elseif ($row.DeployedAt) {
                try {
                    $candidateTime = [datetime]$row.DeployedAt
                }
                catch {
                    $candidateTime = $null
                }
            }

            if ($candidateTime -and ($null -eq $lastUpdated -or $candidateTime -gt $lastUpdated)) {
                $lastUpdated = $candidateTime
            }
        }

        $lifecycleSupportCount = 0
        foreach ($actionName in $parityModel.LifecycleActions) {
            if ($decoyTypeDef."Supports$actionName") {
                $lifecycleSupportCount++
            }
        }

        [PSCustomObject]@{
            Platform                = $decoyTypeDef.Platform
            Family                  = $decoyTypeDef.Family
            DecoyType               = $decoyTypeDef.DecoyType
            ObjectType              = $decoyTypeDef.ObjectType
            SupportsDeploy          = [bool]$decoyTypeDef.SupportsDeploy
            SupportsUpdate          = [bool]$decoyTypeDef.SupportsUpdate
            SupportsDisable         = [bool]$decoyTypeDef.SupportsDisable
            SupportsEnable          = [bool]$decoyTypeDef.SupportsEnable
            SupportsRemove          = [bool]$decoyTypeDef.SupportsRemove
            LifecycleSupportCount   = $lifecycleSupportCount
            LifecycleSupportPercent = [math]::Round(($lifecycleSupportCount / [double]$parityModel.LifecycleActions.Count) * 100, 2)
            TotalCount              = $rowsForType.Count
            ActiveCount             = $activeForType.Count
            RemovedCount            = $removedForType.Count
            OpportunityCount        = if ($opportunityCounts.ContainsKey($decoyTypeDef.DecoyType)) { [int]$opportunityCounts[$decoyTypeDef.DecoyType] } else { 0 }
            LastSeen                = $lastUpdated
        }
    }

    $familyStatus = foreach ($familyDef in $parityModel.FamilyMappings) {
        $adActive = @(
            $activeRows | Where-Object {
                [string]$_.Platform -eq 'AD' -and
                $familyDef.ADDecoyTypes -contains [string]$_.DecoyType
            }
        ).Count

        $entraActive = @(
            $activeRows | Where-Object {
                [string]$_.Platform -eq 'Entra' -and
                $familyDef.EntraDecoyTypes -contains [string]$_.DecoyType
            }
        ).Count

        $requiredEntra = [int][math]::Ceiling($adActive * $TargetParityRatio)
        $gap = [Math]::Max($requiredEntra - $entraActive, 0)

        [PSCustomObject]@{
            Family             = $familyDef.Family
            Description        = $familyDef.Description
            ADActiveCount      = $adActive
            EntraActiveCount   = $entraActive
            TargetEntraCount   = $requiredEntra
            Gap                = $gap
            IsMet              = ($gap -le 0)
            ADDecoyTypes       = @($familyDef.ADDecoyTypes)
            EntraDecoyTypes    = @($familyDef.EntraDecoyTypes)
            SuggestedDecoyType = if ($familyDef.EntraDecoyTypes.Count -gt 0) { $familyDef.EntraDecoyTypes[0] } else { $null }
        }
    }

    $adMatrix = @($coverageMatrix | Where-Object { $_.Platform -eq 'AD' })
    $entraMatrix = @($coverageMatrix | Where-Object { $_.Platform -eq 'Entra' })

    $GetPlatformCoveragePercent = {
        param([System.Object[]]$Rows)

        if (-not $Rows -or $Rows.Count -eq 0) {
            return 0
        }

        $totalSupported = ($Rows | Measure-Object -Property LifecycleSupportCount -Sum).Sum
        $maxSupported = $Rows.Count * $parityModel.LifecycleActions.Count
        if ($maxSupported -le 0) {
            return 0
        }

        return [math]::Round(($totalSupported / [double]$maxSupported) * 100, 2)
    }

    $adLifecycleCoverage = & $GetPlatformCoveragePercent -Rows $adMatrix
    $entraLifecycleCoverage = & $GetPlatformCoveragePercent -Rows $entraMatrix

    $activeADDecoys = @($activeRows | Where-Object { [string]$_.Platform -eq 'AD' }).Count
    $activeEntraDecoys = @($activeRows | Where-Object { [string]$_.Platform -eq 'Entra' }).Count

    $entraToAdRatio = if ($activeADDecoys -gt 0) {
        [math]::Round(($activeEntraDecoys / [double]$activeADDecoys), 4)
    }
    elseif ($activeEntraDecoys -gt 0) {
        [double]::PositiveInfinity
    }
    else {
        1.0
    }

    $missingFamilies = @($familyStatus | Where-Object { -not $_.IsMet })
    $recommendations = [System.Collections.Generic.List[string]]::new()
    foreach ($familyGap in $missingFamilies) {
        $recommendations.Add("Increase Entra '$($familyGap.Family)' coverage by at least $($familyGap.Gap) decoy(s), prioritizing '$($familyGap.SuggestedDecoyType)'.")
    }

    if ($missingFamilies.Count -eq 0) {
        $recommendations.Add('Entra parity target is currently met for all mapped families.')
    }

    return [PSCustomObject]@{
        Timestamp                   = Get-Date
        Source                      = $Source
        TargetParityRatio           = $TargetParityRatio
        ActiveADDecoys              = $activeADDecoys
        ActiveEntraDecoys           = $activeEntraDecoys
        EntraToADActiveRatio        = $entraToAdRatio
        ADLifecycleCoveragePercent  = $adLifecycleCoverage
        EntraLifecycleCoveragePercent = $entraLifecycleCoverage
        IsParityMet                 = ($missingFamilies.Count -eq 0)
        MissingFamilyCount          = $missingFamilies.Count
        Recommendations             = @($recommendations)
        FamilyStatus                = @($familyStatus)
        Matrix                      = @($coverageMatrix)
    }
}
