<#
.SYNOPSIS
    Generates incident-response playbook templates for High/Critical token triggers.

.DESCRIPTION
    Builds a markdown playbook file with severity-specific response SLAs, immediate
    actions, investigation checklist, and current affected decoy identities from
    `Get-F4keH0undInventory`.

    Optionally enriches each listed identity with redesign recommendations from
    `Test-F4keH0undDrift` when available.

.PARAMETER AlertSeverity
    Target severity profile for playbook generation: `High` or `Critical`.

.PARAMETER Identity
    Optional list of specific decoy identities to include.

.PARAMETER Source
    Inventory source used for playbook context (`Auto`, `Events`, `Reports`).

.PARAMETER IncludeRemoved
    Includes removed entries when querying events inventory.

.PARAMETER PreferSnapshot
    Prefers snapshot cache for events inventory.

.PARAMETER SkipLiveStatus
    Controls AD live-status verification during inventory reads.
    Defaults to lightweight mode (`$true`) unless explicitly passed.

.PARAMETER Server
    Optional Domain Controller for AD live checks.

.PARAMETER Credential
    Optional credential for AD live checks.

.PARAMETER MaxFindings
    Maximum number of matching inventory rows to include.

.PARAMETER OutputPath
    Output markdown path. When omitted, writes to:
    `./Docs/Playbooks/TokenTrigger-<Severity>-<Timestamp>.md`.

.EXAMPLE
    ./scripts/New-TokenTriggerResponsePlaybook.ps1 -AlertSeverity High

.EXAMPLE
    ./scripts/New-TokenTriggerResponsePlaybook.ps1 -AlertSeverity Critical -Identity fhlg-win-cloudapicanarytokendecoy-a1b2c3 -Source Events -PreferSnapshot
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('High', 'Critical')]
    [string]$AlertSeverity = 'High',

    [Parameter()]
    [string[]]$Identity,

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
    [ValidateRange(1, 250)]
    [int]$MaxFindings = 25,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$repoRoot = Split-Path -Path $scriptRoot -Parent
$moduleManifestPath = Join-Path -Path $repoRoot -ChildPath 'F4keH0und.psd1'

if (-not (Test-Path -Path $moduleManifestPath -PathType Leaf)) {
    throw "Module manifest not found at '$moduleManifestPath'. Run this script from repository context."
}

Import-Module $moduleManifestPath -Force

$timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$outputResolvedPath = if ($PSBoundParameters.ContainsKey('OutputPath')) {
    $OutputPath
}
else {
    Join-Path -Path $repoRoot -ChildPath "Docs/Playbooks/TokenTrigger-$AlertSeverity-$timestampUtc.md"
}

$outputDirectory = Split-Path -Path $outputResolvedPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

$minAlertScore = if ($AlertSeverity -eq 'Critical') { 85 } else { 65 }

$inventoryParams = @{
    Source        = $Source
    AlertSeverity = @($AlertSeverity)
    MinAlertScore = $minAlertScore
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
    Write-Warning "Failed to read inventory for playbook context. Continuing with empty findings. Error: $($_.Exception.Message)"
    $inventoryRows = @()
}

if ($PSBoundParameters.ContainsKey('Identity') -and @($Identity).Count -gt 0) {
    $inventoryRows = @(
        $inventoryRows | Where-Object {
            @($Identity) -contains [string]$_.Identity
        }
    )
}

$inventoryRows = @(
    $inventoryRows |
        Sort-Object -Property @{ Expression = 'AlertScore'; Descending = $true }, @{ Expression = 'LastUpdated'; Descending = $true } |
        Select-Object -First $MaxFindings
)

$driftRowsByIdentity = @{}
try {
    $driftRows = @(Test-F4keH0undDrift -Source $Source -PreferSnapshot:$PreferSnapshot -IncludeRemoved:$IncludeRemoved -SkipLiveStatus:$inventoryParams['SkipLiveStatus'] -AsList)
    foreach ($driftRow in $driftRows) {
        $driftIdentity = [string]$driftRow.Identity
        if ([string]::IsNullOrWhiteSpace($driftIdentity)) {
            continue
        }

        if (-not $driftRowsByIdentity.ContainsKey($driftIdentity)) {
            $driftRowsByIdentity[$driftIdentity] = $driftRow
        }
    }
}
catch {
    Write-Verbose "Drift recommendation enrichment unavailable. Error: $($_.Exception.Message)"
}

$slaSection = if ($AlertSeverity -eq 'Critical') {
@'
## Severity SLA (`Critical`)

- Acknowledge incident: **within 5 minutes**
- Assign Incident Commander + secondary analyst: **within 10 minutes**
- Containment action initiated: **within 15 minutes**
- Escalation to identity/platform owner: **immediate**
'@
}
else {
@'
## Severity SLA (`High`)

- Acknowledge incident: **within 15 minutes**
- Assign primary analyst: **within 30 minutes**
- Initial containment decision: **within 60 minutes**
- Escalation to platform owner: **within 90 minutes**
'@
}

$immediateActions = if ($AlertSeverity -eq 'Critical') {
@'
## Immediate Actions (0-30 min)

1. Validate trigger authenticity (source event + actor + endpoint).
2. Isolate affected endpoint/session if interactive compromise is suspected.
3. Disable related deceptive element if active attacker interaction is ongoing:
   - Disable-F4keH0undElement -ElementId <Identity> -Reason "Critical trigger containment"
4. Capture volatile context (process tree, logon session, network connections).
5. Notify SOC lead and identity operations owner.
'@
}
else {
@'
## Immediate Actions (0-60 min)

1. Validate trigger authenticity (source event + actor + endpoint).
2. Perform scope triage (single host vs. lateral footprint).
3. If needed, temporarily disable affected element:
   - Disable-F4keH0undElement -ElementId <Identity> -Reason "High trigger triage"
4. Preserve logs and event evidence references.
5. Notify on-call detections engineer.
'@
}

$header = @"
# Token Trigger Response Playbook — $AlertSeverity

- GeneratedAtUtc: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
- Source: $Source
- MinAlertScore: $minAlertScore
- SkipLiveStatusUsed: $($inventoryParams['SkipLiveStatus'])
- FindingsIncluded: $(@($inventoryRows).Count)

This playbook template is auto-generated from current inventory state and aligns to Phase 5 response operations.
"@

$investigation = @'
## Investigation Checklist

- Correlate LastTriggerSource, LastTriggerEvidence, and LastTriggerActor with SIEM timeline.
- Determine if token canary interaction is **correlated** (TokenCorrelationStatus = Correlated).
- Check whether trigger aligns with approved admin/test activity.
- Enumerate touched identities/hosts around first and last trigger timestamps.
- Classify blast radius (single identity, host cluster, or cross-plane identity abuse).

## Containment and Recovery

1. Rotate/refresh deceptive token artifacts for affected elements:
   - Update-F4keH0undElement -ElementId <Identity> -TemplateData @{ CanaryToken = 'fhlg-rotated-<unique>' } -WhatIf
2. Refresh AD/Entra decoy lure context where applicable:
   - Update-F4keH0undDecoy -Identity <Identity> -Platform AD -ObjectType User -Description 'Refreshed lure context' -WhatIf
   - Update-F4keH0undDecoy -Identity <Identity> -Platform Entra -ObjectType ServicePrincipal -Description 'Refreshed lure context' -WhatIf
3. Re-enable previously disabled elements once monitoring controls are in place:
   - Enable-F4keH0undElement -ElementId <Identity> -WhatIf

## Post-Incident Tasks

- Record root cause hypothesis and ATT&CK technique mapping.
- Add/update SIEM suppression rules for known benign trigger patterns.
- Run drift review for redesign candidates:
  - Test-F4keH0undDrift -Source Events -AsList | Sort-Object DriftScore -Descending
- Confirm parity impact if Entra identities were involved:
  - Test-F4keH0undCoverage -Source Events -PreferSnapshot -SkipLiveStatus
'@

$findingLines = [System.Collections.Generic.List[string]]::new()
$findingLines.Add('## Current Findings')
$findingLines.Add('')

if (@($inventoryRows).Count -eq 0) {
    $findingLines.Add('_No matching inventory findings were returned for this severity at generation time._')
}
else {
    $findingLines.Add('| Identity | Platform | DecoyType | AlertScore | TriggerCount | LastTriggerSource | Suggested Redesign |')
    $findingLines.Add('|---|---|---|---:|---:|---|---|')

    foreach ($row in $inventoryRows) {
        $identityValue = [string]$row.Identity
        $suggestedRedesign = 'Review and rotate template as needed.'
        if ($driftRowsByIdentity.ContainsKey($identityValue)) {
            $driftEntry = $driftRowsByIdentity[$identityValue]
            if (-not [string]::IsNullOrWhiteSpace([string]$driftEntry.RecommendedAction)) {
                $suggestedRedesign = [string]$driftEntry.RecommendedAction
            }
        }

        $line = "| $identityValue | $([string]$row.Platform) | $([string]$row.DecoyType) | $([int]$row.AlertScore) | $([int]$row.TriggerCount) | $([string]$row.LastTriggerSource) | $suggestedRedesign |"
        $findingLines.Add($line)
    }
}

$communicationSection = @"
## Communications Template

**Incident Title:** Token Trigger - $AlertSeverity - <Identity/Host>

**Summary:**
At <time>, a $AlertSeverity confidence token-trigger alert was detected by F4keH0und. Initial scope indicates <scope>. Containment status: <status>.

**Next Update:** <time>

**Owners:**
- Incident Commander: <name>
- Detection Engineer: <name>
- Identity Platform Owner: <name>
"@

$contentParts = @(
    $header,
    $slaSection,
    $immediateActions,
    ($findingLines -join [Environment]::NewLine),
    $investigation,
    $communicationSection
)

$content = ($contentParts -join ([Environment]::NewLine + [Environment]::NewLine)).Trim() + [Environment]::NewLine
Set-Content -Path $outputResolvedPath -Value $content -Encoding UTF8

[PSCustomObject]@{
    OutputPath          = (Resolve-Path -Path $outputResolvedPath).Path
    AlertSeverity       = $AlertSeverity
    Source              = $Source
    MinAlertScore       = $minAlertScore
    FindingsIncluded    = @($inventoryRows).Count
    SkipLiveStatusUsed  = [bool]$inventoryParams['SkipLiveStatus']
    GeneratedAtUtc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

