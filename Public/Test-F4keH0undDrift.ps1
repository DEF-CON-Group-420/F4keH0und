<#
.SYNOPSIS
    Performs lightweight drift checks and redesign recommendations for decoys.

.DESCRIPTION
    Evaluates current inventory state for stale deceptive elements and template drift,
    with priority on identity/token artifacts. The command is designed for operational
    Phase 5 hardening workflows and returns actionable redesign suggestions.

    Drift checks include:
    - lifecycle staleness by age threshold,
    - trigger-driven token rotation recommendations,
    - missing token canary/template metadata,
    - missing Entra lure-theme metadata.

    By default, this command performs a lightweight inventory read by skipping AD
    live status checks unless `-SkipLiveStatus:$false` is explicitly provided.

.PARAMETER Source
    Inventory source used by Get-F4keH0undInventory.

.PARAMETER IncludeRemoved
    Includes removed lifecycle entries when using events source.

.PARAMETER PreferSnapshot
    Prefer snapshot cache before event-log replay for events source.

.PARAMETER SkipLiveStatus
    Controls live AD status checks during inventory read. Defaults to lightweight
    behavior (`$true`) when not explicitly passed.

.PARAMETER Server
    Optional Domain Controller for AD live status checks.

.PARAMETER Credential
    Optional credential for AD live status checks.

.PARAMETER Platform
    Optional platform filter (`AD`, `Entra`, `Windows`).

.PARAMETER MaxArtifactAgeDays
    Maximum allowed age (days) for non-token artifacts before drift is flagged.

.PARAMETER MaxTokenAgeDays
    Maximum allowed age (days) for token/identity decoys before drift is flagged.

.PARAMETER MinTriggerCountForRedesign
    Minimum trigger count required before recommending immediate redesign/rotation.

.PARAMETER IncludeCompliant
    Includes non-drifted rows in output.

.PARAMETER AsList
    Returns only per-element drift rows rather than a summary object.

.EXAMPLE
    Test-F4keH0undDrift -Source Events -PreferSnapshot

.EXAMPLE
    Test-F4keH0undDrift -Platform Windows -MaxTokenAgeDays 14 -AsList |
      Format-Table Identity,DriftSeverity,DriftScore,RecommendedAction -AutoSize
#>
function Test-F4keH0undDrift {
    [CmdletBinding()]
    [OutputType([PSObject], [System.Object[]])]
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
        [ValidateSet('AD', 'Entra', 'Windows')]
        [string[]]$Platform,

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$MaxArtifactAgeDays = 45,

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$MaxTokenAgeDays = 21,

        [Parameter()]
        [ValidateRange(1, 500)]
        [int]$MinTriggerCountForRedesign = 1,

        [Parameter()]
        [switch]$IncludeCompliant,

        [Parameter()]
        [switch]$AsList
    )

    $resolveDate = {
        param(
            [Parameter()]
            [object]$Value
        )

        if ($null -eq $Value) {
            return $null
        }

        try {
            return [datetime]$Value
        }
        catch {
            return $null
        }
    }

    $resolveInteger = {
        param(
            [Parameter()]
            [object]$Value,

            [Parameter()]
            [int]$Default
        )

        if ($null -eq $Value) {
            return $Default
        }

        try {
            return [int]$Value
        }
        catch {
            return $Default
        }
    }

    $resolveRecommendation = {
        param(
            [Parameter(Mandatory = $true)]
            [PSObject]$Row,

            [Parameter(Mandatory = $true)]
            [string[]]$ReasonCodes
        )

        $platformValue = [string]$Row.Platform
        $identityValue = [string]$Row.Identity
        $objectTypeValue = [string]$Row.ObjectType

        if ($platformValue -eq 'Windows') {
            if (@($ReasonCodes) -contains 'TokenCanaryMissing' -or @($ReasonCodes) -contains 'TriggerRotationRecommended') {
                return [PSCustomObject]@{
                    Action  = 'Rotate token template values and redeploy element artifacts.'
                    Command = "Update-F4keH0undElement -ElementId '$identityValue' -TemplateData @{ CanaryToken = 'fhlg-rotated-<unique>' } -WhatIf"
                }
            }

            return [PSCustomObject]@{
                Action  = 'Refresh Windows artifact template and redeploy element files.'
                Command = "Update-F4keH0undElement -ElementId '$identityValue' -WhatIf"
            }
        }

        if ($platformValue -eq 'Entra') {
            $entraType = if ([string]::IsNullOrWhiteSpace($objectTypeValue)) { 'ServicePrincipal' } else { $objectTypeValue }
            return [PSCustomObject]@{
                Action  = 'Refresh Entra lure metadata/description to redesign exposed context.'
                Command = "Update-F4keH0undDecoy -Identity '$identityValue' -Platform Entra -ObjectType $entraType -Description 'Refreshed lure context' -WhatIf"
            }
        }

        $adType = if ([string]::IsNullOrWhiteSpace($objectTypeValue)) { 'User' } else { $objectTypeValue }
        return [PSCustomObject]@{
            Action  = 'Refresh AD decoy presentation to reduce pattern drift.'
            Command = "Update-F4keH0undDecoy -Identity '$identityValue' -Platform AD -ObjectType $adType -Description 'Refreshed decoy context' -WhatIf"
        }
    }

    $inventoryParams = @{
        Source = $Source
    }
    if ($IncludeRemoved) { $inventoryParams['IncludeRemoved'] = $true }
    if ($PreferSnapshot) { $inventoryParams['PreferSnapshot'] = $true }
    if ($PSBoundParameters.ContainsKey('SkipLiveStatus')) {
        $inventoryParams['SkipLiveStatus'] = [bool]$SkipLiveStatus
    }
    else {
        $inventoryParams['SkipLiveStatus'] = $true
    }
    if ($PSBoundParameters.ContainsKey('Server')) { $inventoryParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $inventoryParams['Credential'] = $Credential }

    $inventoryRows = @()
    try {
        $inventoryRows = @(Get-F4keH0undInventory @inventoryParams)
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to load inventory. Returning empty drift assessment. Error: $($_.Exception.Message)"
        $inventoryRows = @()
    }

    if ($PSBoundParameters.ContainsKey('Platform') -and @($Platform).Count -gt 0) {
        $inventoryRows = @(
            $inventoryRows | Where-Object {
                @($Platform) -contains [string]$_.Platform
            }
        )
    }

    $nowUtc = (Get-Date).ToUniversalTime()
    $findings = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($row in $inventoryRows) {
        $metadata = Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $row.Metadata
        $templateData = if ($metadata.ContainsKey('TemplateData')) {
            Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $metadata['TemplateData']
        }
        else {
            @{}
        }

        $platformValue = [string]$row.Platform
        $decoyTypeValue = [string]$row.DecoyType
        $alertSeverity = if ($row.PSObject.Properties.Name -contains 'AlertSeverity') {
            [string]$row.AlertSeverity
        }
        else {
            'None'
        }

        $triggerCount = & $resolveInteger -Value $(
            if ($row.PSObject.Properties.Name -contains 'TriggerCount') {
                $row.TriggerCount
            }
            else {
                0
            }
        ) -Default 0

        $lastUpdated = & $resolveDate -Value $(
            if ($row.PSObject.Properties.Name -contains 'LastUpdated') {
                $row.LastUpdated
            }
            else {
                $null
            }
        )
        $deployedAt = & $resolveDate -Value $(
            if ($row.PSObject.Properties.Name -contains 'DeployedAt') {
                $row.DeployedAt
            }
            else {
                $null
            }
        )
        $lastTriggeredAt = & $resolveDate -Value $(
            if ($row.PSObject.Properties.Name -contains 'LastTriggeredAt') {
                $row.LastTriggeredAt
            }
            else {
                $null
            }
        )

        $referenceTime = if ($lastUpdated) { $lastUpdated } else { $deployedAt }
        $ageDays = if ($referenceTime) {
            [int][Math]::Floor(($nowUtc - $referenceTime.ToUniversalTime()).TotalDays)
        }
        else {
            $null
        }

        $isTokenFamily = $decoyTypeValue -match '(?i)token|credential|identity'
        $ageThresholdDays = if ($isTokenFamily) { $MaxTokenAgeDays } else { $MaxArtifactAgeDays }

        $reasonCodes = [System.Collections.Generic.List[string]]::new()
        $reasonMessages = [System.Collections.Generic.List[string]]::new()
        $driftScore = 0

        if ($null -eq $referenceTime) {
            $reasonCodes.Add('NoLifecycleTimestamp')
            $reasonMessages.Add('No valid LastUpdated/DeployedAt timestamp available for age checks.')
            $driftScore += 25
        }
        elseif ($ageDays -gt $ageThresholdDays) {
            $overflowDays = [int]($ageDays - $ageThresholdDays)
            $ageContribution = 30 + [Math]::Min(20, $overflowDays)
            $driftScore += $ageContribution
            $reasonCodes.Add('AgeThresholdExceeded')
            $reasonMessages.Add("Element age is $ageDays day(s), exceeding threshold $ageThresholdDays day(s).")
        }

        if ($triggerCount -ge $MinTriggerCountForRedesign) {
            $triggerContribution = 25 + [Math]::Min(20, [Math]::Max(1, $triggerCount - $MinTriggerCountForRedesign + 1) * 5)
            $driftScore += $triggerContribution
            $reasonCodes.Add('TriggerRotationRecommended')
            $reasonMessages.Add("TriggerCount is $triggerCount (threshold: $MinTriggerCountForRedesign); redesign/rotation recommended.")
        }

        switch ($alertSeverity) {
            'Critical' {
                $driftScore += 25
                $reasonCodes.Add('CriticalAlertSeverity')
                $reasonMessages.Add('Inventory alert severity is Critical.')
            }
            'High' {
                $driftScore += 15
                $reasonCodes.Add('HighAlertSeverity')
                $reasonMessages.Add('Inventory alert severity is High.')
            }
        }

        if ($platformValue -eq 'Windows') {
            if (-not $metadata.ContainsKey('TemplateData')) {
                $driftScore += 20
                $reasonCodes.Add('TemplateDataMissing')
                $reasonMessages.Add('Windows element metadata does not include TemplateData.')
            }

            if ($isTokenFamily -and -not $templateData.ContainsKey('CanaryToken')) {
                $driftScore += 30
                $reasonCodes.Add('TokenCanaryMissing')
                $reasonMessages.Add('Token/identity element template is missing CanaryToken.')
            }

            if (-not $metadata.ContainsKey('TelemetryProfile')) {
                $driftScore += 10
                $reasonCodes.Add('TelemetryProfileMissing')
                $reasonMessages.Add('Windows element metadata does not include TelemetryProfile.')
            }
        }

        if ($platformValue -eq 'Entra' -and $decoyTypeValue -like 'Entra*') {
            $lureTheme = if ($metadata.ContainsKey('LureTheme')) { [string]$metadata['LureTheme'] } else { $null }
            if ([string]::IsNullOrWhiteSpace($lureTheme)) {
                $driftScore += 20
                $reasonCodes.Add('LureThemeMissing')
                $reasonMessages.Add('Entra decoy metadata is missing LureTheme.')
            }
        }

        $drifted = $reasonCodes.Count -gt 0
        if (-not $drifted -and -not $IncludeCompliant) {
            continue
        }

        if ($drifted) {
            $driftScore = [Math]::Max(0, [Math]::Min(100, [int]$driftScore))
        }
        else {
            $driftScore = 0
        }

        $driftSeverity = if (-not $drifted) {
            'None'
        }
        elseif ($driftScore -ge 85) {
            'Critical'
        }
        elseif ($driftScore -ge 65) {
            'High'
        }
        elseif ($driftScore -ge 40) {
            'Medium'
        }
        else {
            'Low'
        }

        $recommendation = if ($drifted) {
            & $resolveRecommendation -Row $row -ReasonCodes @($reasonCodes)
        }
        else {
            [PSCustomObject]@{
                Action  = 'No redesign required.'
                Command = $null
            }
        }

        $findings.Add([PSCustomObject]@{
            Identity         = [string]$row.Identity
            Platform         = $platformValue
            DecoyType        = $decoyTypeValue
            ObjectType       = [string]$row.ObjectType
            Status           = [string]$row.Status
            IsActive         = [bool]($row.IsActive -ne $false)
            Drifted          = $drifted
            DriftScore       = [int]$driftScore
            DriftSeverity    = $driftSeverity
            DriftReasonCodes = @($reasonCodes)
            DriftReasons     = @($reasonMessages)
            AgeDays          = $ageDays
            AgeThresholdDays = [int]$ageThresholdDays
            TriggerCount     = [int]$triggerCount
            AlertSeverity    = $alertSeverity
            LastUpdated      = $lastUpdated
            LastTriggeredAt  = $lastTriggeredAt
            RecommendedAction = [string]$recommendation.Action
            SuggestedCommand = [string]$recommendation.Command
        })
    }

    $orderedFindings = @(
        $findings | Sort-Object -Property @{ Expression = 'DriftScore'; Descending = $true }, @{ Expression = 'LastUpdated'; Descending = $true }, Identity
    )

    if ($AsList) {
        return @($orderedFindings)
    }

    $driftedFindings = @($orderedFindings | Where-Object { $_.Drifted })

    $severityCounts = [ordered]@{
        Critical = @($driftedFindings | Where-Object { $_.DriftSeverity -eq 'Critical' }).Count
        High     = @($driftedFindings | Where-Object { $_.DriftSeverity -eq 'High' }).Count
        Medium   = @($driftedFindings | Where-Object { $_.DriftSeverity -eq 'Medium' }).Count
        Low      = @($driftedFindings | Where-Object { $_.DriftSeverity -eq 'Low' }).Count
    }

    return [PSCustomObject]@{
        GeneratedAtUtc            = $nowUtc
        Source                    = $Source
        SkipLiveStatusUsed        = [bool]$inventoryParams['SkipLiveStatus']
        TotalEvaluated            = @($inventoryRows).Count
        DriftedCount              = $driftedFindings.Count
        DriftSeverityCounts       = [PSCustomObject]$severityCounts
        MaxArtifactAgeDays        = [int]$MaxArtifactAgeDays
        MaxTokenAgeDays           = [int]$MaxTokenAgeDays
        MinTriggerCountForRedesign = [int]$MinTriggerCountForRedesign
        Findings                  = @($orderedFindings)
    }
}
