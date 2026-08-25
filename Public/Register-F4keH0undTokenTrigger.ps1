<#
.SYNOPSIS
    Registers token/identity trigger telemetry for deceptive elements.

.DESCRIPTION
    Writes a `Trigger` inventory event correlated to an existing decoy/element
    identity and updates alert-scoring fields in the persistent inventory state.

    This command is intended for SIEM/SOAR workflows that detect token access,
    credential lure interaction, or suspicious API secret use.

.PARAMETER Identity
    Inventory identity (for example element ID or decoy identity) to correlate.

    Optional when `-ConnectorPreset` and `-TelemetryPayload` are provided and
    the payload contains a mapped identity field.

.PARAMETER ConnectorPreset
    Optional telemetry connector preset ID used to normalize SIEM/SOAR payloads
    into trigger fields.

.PARAMETER TelemetryPayload
    Optional raw telemetry payload object (hashtable/PSObject) used with
    `-ConnectorPreset` for field mapping.

.PARAMETER DecoyType
    Optional decoy/element type override. If omitted, resolved from inventory.

.PARAMETER Platform
    Optional platform override. If omitted, resolved from inventory.

.PARAMETER ObjectType
    Optional object type override. If omitted, resolved from inventory.

.PARAMETER TriggerType
    Trigger classification.

.PARAMETER TriggerSource
    Source of the trigger telemetry (for example `Sysmon:EventID11`).

.PARAMETER Actor
    Optional actor identity (user/process/host) tied to the trigger.

.PARAMETER ComputerName
    Optional host where trigger was observed.

.PARAMETER EvidenceRef
    Optional evidence reference (event ID, case link, artifact path).

.PARAMETER TokenIdentifier
    Optional token fingerprint identifier (recommended: `sha256:<short>`).

.PARAMETER TokenValue
    Optional raw token value. If provided, it is converted to fingerprint and
    only the fingerprint is stored in inventory metadata.

.PARAMETER SignalCount
    Number of correlated telemetry signals represented by this event.

.PARAMETER Confidence
    Trigger confidence score (0-100).

.PARAMETER Correlated
    Hint that upstream detection has already confirmed token correlation.

.PARAMETER PassThru
    Returns updated inventory row(s) for the specified identity.

.EXAMPLE
    Register-F4keH0undTokenTrigger -Identity fhlg-win-cloudapicanarytokendecoy-a1b2c3d4e5f6 -TriggerType ApiAuth -TriggerSource 'Sysmon:EventID3' -SignalCount 3 -Confidence 90

.EXAMPLE
    Register-F4keH0undTokenTrigger -Identity svc_legacy_sync -Platform AD -ObjectType User -TriggerType CredentialUse -TokenValue 'decoy-passphrase' -PassThru

.EXAMPLE
    Register-F4keH0undTokenTrigger -ConnectorPreset SysmonEvent11FileCreate -TelemetryPayload @{ Identity = 'fhlg-win-identitybreadcrumbtokendecoy-a1b2c3d4e5f6'; User = 'CORP\j.smith'; Computer = 'WIN-APP-01'; EventRecordId = '42755'; TargetFilename = 'C:\ProgramData\F4keH0und-LG\Elements\identity\notes.txt' } -PassThru
#>
function Register-F4keH0undTokenTrigger {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$Identity,

        [Parameter()]
        [string]$ConnectorPreset,

        [Parameter()]
        [object]$TelemetryPayload,

        [Parameter()]
        [string]$DecoyType,

        [Parameter()]
        [ValidateSet('AD', 'Entra', 'Windows')]
        [string]$Platform,

        [Parameter()]
        [string]$ObjectType,

        [Parameter()]
        [ValidateSet('TokenUse', 'CredentialUse', 'ApiAuth', 'FileAccess', 'ProcessAccess', 'NetworkAccess', 'ManualInvestigation', 'Other')]
        [string]$TriggerType = 'TokenUse',

        [Parameter()]
        [string]$TriggerSource,

        [Parameter()]
        [string]$Actor,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [string]$EvidenceRef,

        [Parameter()]
        [string]$TokenIdentifier,

        [Parameter()]
        [string]$TokenValue,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$SignalCount = 1,

        [Parameter()]
        [ValidateRange(0, 100)]
        [double]$Confidence = 80,

        [Parameter()]
        [switch]$Correlated,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $results = [System.Collections.Generic.List[PSObject]]::new()
        $inventoryState = @(Get-F4keH0undInventoryState -IncludeRemoved)
        $requestedIdentities = [System.Collections.Generic.List[string]]::new()
        $connectorContext = $null

        $usesConnectorPreset = $PSBoundParameters.ContainsKey('ConnectorPreset')
        $usesTelemetryPayload = $PSBoundParameters.ContainsKey('TelemetryPayload')

        if ($usesConnectorPreset -xor $usesTelemetryPayload) {
            Write-Error "[$($MyInvocation.MyCommand)] - Connector mode requires both -ConnectorPreset and -TelemetryPayload."
            return
        }

        if ($usesConnectorPreset) {
            try {
                $connectorContext = Convert-PrivateF4keH0undTelemetryPayloadToTriggerContext -PresetId $ConnectorPreset -Payload $TelemetryPayload
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to parse telemetry payload using preset '$ConnectorPreset'. Error: $($_.Exception.Message)"
                return
            }
        }
    }

    process {
        foreach ($identityCandidate in @($Identity)) {
            $identityText = [string]$identityCandidate
            if (-not [string]::IsNullOrWhiteSpace($identityText) -and -not $requestedIdentities.Contains($identityText)) {
                $requestedIdentities.Add($identityText)
            }
        }
    }

    end {
        $effectiveIdentities = [System.Collections.Generic.List[string]]::new()
        if ($requestedIdentities.Count -gt 0) {
            foreach ($identityText in @($requestedIdentities)) {
                if (-not $effectiveIdentities.Contains([string]$identityText)) {
                    $effectiveIdentities.Add([string]$identityText)
                }
            }
        }
        elseif ($null -ne $connectorContext) {
            foreach ($identityText in @($connectorContext.Identity)) {
                $identityValue = [string]$identityText
                if (-not [string]::IsNullOrWhiteSpace($identityValue) -and -not $effectiveIdentities.Contains($identityValue)) {
                    $effectiveIdentities.Add($identityValue)
                }
            }
        }

        if ($effectiveIdentities.Count -eq 0) {
            Write-Error "[$($MyInvocation.MyCommand)] - No identity resolved. Provide -Identity or a payload field mapped by the selected ConnectorPreset."
            return
        }

        $effectiveTriggerType = if ($PSBoundParameters.ContainsKey('TriggerType')) {
            [string]$TriggerType
        }
        elseif ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.TriggerType)) {
            [string]$connectorContext.TriggerType
        }
        else {
            [string]$TriggerType
        }

        $effectiveTriggerSource = if ($PSBoundParameters.ContainsKey('TriggerSource')) {
            [string]$TriggerSource
        }
        elseif ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.TriggerSource)) {
            [string]$connectorContext.TriggerSource
        }
        else {
            $null
        }

        $effectiveActor = if ($PSBoundParameters.ContainsKey('Actor')) {
            [string]$Actor
        }
        elseif ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.Actor)) {
            [string]$connectorContext.Actor
        }
        else {
            $null
        }

        $effectiveComputerName = if ($PSBoundParameters.ContainsKey('ComputerName')) {
            [string]$ComputerName
        }
        elseif ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.ComputerName)) {
            [string]$connectorContext.ComputerName
        }
        else {
            $null
        }

        $effectiveEvidenceRef = if ($PSBoundParameters.ContainsKey('EvidenceRef')) {
            [string]$EvidenceRef
        }
        elseif ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.EvidenceRef)) {
            [string]$connectorContext.EvidenceRef
        }
        else {
            $null
        }

        $effectiveSignalCount = if ($PSBoundParameters.ContainsKey('SignalCount')) {
            [int]$SignalCount
        }
        elseif ($connectorContext -and [int]$connectorContext.SignalCount -gt 0) {
            [int]$connectorContext.SignalCount
        }
        else {
            [int]$SignalCount
        }

        $effectiveConfidence = if ($PSBoundParameters.ContainsKey('Confidence')) {
            [double]$Confidence
        }
        elseif ($connectorContext -and [double]$connectorContext.Confidence -ge 0 -and [double]$connectorContext.Confidence -le 100) {
            [double]$connectorContext.Confidence
        }
        else {
            [double]$Confidence
        }

        $effectiveCorrelated = if ($PSBoundParameters.ContainsKey('Correlated')) {
            [bool]$Correlated
        }
        elseif ($connectorContext -and [bool]$connectorContext.Correlated) {
            $true
        }
        else {
            $false
        }

        $connectorTokenIdentifier = if ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.TokenIdentifier)) {
            [string]$connectorContext.TokenIdentifier
        }
        else {
            $null
        }

        $effectiveTokenIdentifier = if ($PSBoundParameters.ContainsKey('TokenIdentifier')) {
            [string]$TokenIdentifier
        }
        elseif ($PSBoundParameters.ContainsKey('TokenValue')) {
            Get-PrivateF4keH0undTokenFingerprint -Value $TokenValue
        }
        elseif (-not [string]::IsNullOrWhiteSpace($connectorTokenIdentifier)) {
            Get-PrivateF4keH0undTokenFingerprint -Value $connectorTokenIdentifier
        }
        else {
            $null
        }

        foreach ($currentIdentity in @($effectiveIdentities)) {
            if ([string]::IsNullOrWhiteSpace($currentIdentity)) {
                continue
            }

            $matchedRow = @($inventoryState | Where-Object { [string]$_.Identity -eq [string]$currentIdentity } | Sort-Object -Property @{ Expression = 'LastUpdated'; Descending = $true } | Select-Object -First 1)
            $resolvedRow = if ($matchedRow.Count -gt 0) { $matchedRow[0] } else { $null }

            $resolvedDecoyType = if ($PSBoundParameters.ContainsKey('DecoyType')) {
                $DecoyType
            }
            elseif ($resolvedRow -and $resolvedRow.DecoyType) {
                [string]$resolvedRow.DecoyType
            }
            else {
                'UnknownDecoy'
            }

            $resolvedPlatform = if ($PSBoundParameters.ContainsKey('Platform')) {
                $Platform
            }
            elseif ($resolvedRow -and $resolvedRow.Platform) {
                [string]$resolvedRow.Platform
            }
            else {
                'Windows'
            }

            $resolvedObjectType = if ($PSBoundParameters.ContainsKey('ObjectType')) {
                $ObjectType
            }
            elseif ($resolvedRow -and $resolvedRow.ObjectType) {
                [string]$resolvedRow.ObjectType
            }
            else {
                'Element'
            }

            $resolvedLocation = if ($resolvedRow -and $resolvedRow.Location) {
                [string]$resolvedRow.Location
            }
            else {
                $null
            }

            $eventMetadata = @{
                TriggerType   = $effectiveTriggerType
                TriggerSource = $effectiveTriggerSource
                Actor         = $effectiveActor
                ComputerName  = $effectiveComputerName
                EvidenceRef   = $effectiveEvidenceRef
                SignalCount   = $effectiveSignalCount
                Confidence    = [double]$effectiveConfidence
            }
            if (-not [string]::IsNullOrWhiteSpace($effectiveTokenIdentifier)) {
                $eventMetadata['TokenIdentifier'] = $effectiveTokenIdentifier
            }
            if ($effectiveCorrelated) {
                $eventMetadata['CorrelationHint'] = 'Correlated'
            }
            if ($connectorContext -and -not [string]::IsNullOrWhiteSpace([string]$connectorContext.PresetId)) {
                $eventMetadata['ConnectorPreset'] = [string]$connectorContext.PresetId
            }

            $target = "${resolvedPlatform}:$currentIdentity"
            $action = "Register $effectiveTriggerType trigger"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                Write-F4keH0undInventoryEvent -Action 'Trigger' -Identity $currentIdentity -DecoyType $resolvedDecoyType -Platform $resolvedPlatform -ObjectType $resolvedObjectType -Status 'Triggered' -Location $resolvedLocation -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name

                if ($PassThru) {
                    $updatedRows = @(Get-F4keH0undInventoryState -IncludeRemoved | Where-Object { [string]$_.Identity -eq [string]$currentIdentity } | Sort-Object -Property @{ Expression = 'LastUpdated'; Descending = $true } | Select-Object -First 1)
                    foreach ($updatedRow in $updatedRows) {
                        $results.Add($updatedRow)
                    }
                }
            }
        }

        if ($PassThru) {
            return @($results)
        }

        return [PSCustomObject]@{
            IdentityCount = @($effectiveIdentities).Count
            TriggerType   = $effectiveTriggerType
            Platform      = if ($PSBoundParameters.ContainsKey('Platform')) { $Platform } else { 'Mixed' }
            Status        = 'Recorded'
        }
    }
}
