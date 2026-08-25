function Convert-PrivateF4keH0undTelemetryObjectToHashtable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [object]$InputObject
    )

    $result = @{}
    if ($null -eq $InputObject) {
        return $result
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($keyObject in $InputObject.Keys) {
            $result[[string]$keyObject] = $InputObject[$keyObject]
        }
        return $result
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        $result[[string]$property.Name] = $property.Value
    }

    return $result
}

function Get-PrivateF4keH0undDefaultTelemetryConnectorPack {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    return [PSCustomObject]@{
        Version = '1.0'
        Platform = 'Windows'
        Presets = @(
            [PSCustomObject]@{
                PresetId = 'SysmonEvent11FileCreate'
                TriggerType = 'FileAccess'
                TriggerSource = 'Sysmon:EventID11'
                SignalCount = 2
                Confidence = 86
                CorrelationHint = 'Unknown'
                FieldMap = [PSCustomObject]@{
                    Identity = @('Identity', 'DecoyIdentity', 'ElementId', 'TargetIdentity', 'RuleName')
                    Actor = @('User', 'UserName', 'SubjectUserName', 'Image')
                    ComputerName = @('Computer', 'ComputerName', 'Host', 'Hostname')
                    EvidenceRef = @('EventRecordId', 'RecordId', 'EventId', 'CaseId')
                    TokenIdentifier = @('TokenIdentifier', 'TokenFingerprint', 'FileHash', 'TargetFilename')
                }
            }
            [PSCustomObject]@{
                PresetId = 'SysmonEvent3NetworkConnect'
                TriggerType = 'ApiAuth'
                TriggerSource = 'Sysmon:EventID3'
                SignalCount = 3
                Confidence = 90
                CorrelationHint = 'Unknown'
                FieldMap = [PSCustomObject]@{
                    Identity = @('Identity', 'DecoyIdentity', 'ElementId', 'TargetIdentity', 'RuleName')
                    Actor = @('User', 'UserName', 'SubjectUserName', 'Image')
                    ComputerName = @('Computer', 'ComputerName', 'Host', 'Hostname')
                    EvidenceRef = @('EventRecordId', 'RecordId', 'EventId', 'CaseId')
                    TokenIdentifier = @('TokenIdentifier', 'TokenFingerprint', 'DestinationHostname', 'DestinationIp')
                }
            }
            [PSCustomObject]@{
                PresetId = 'WindowsSecurity4624Logon'
                TriggerType = 'CredentialUse'
                TriggerSource = 'WindowsSecurity:EventID4624'
                SignalCount = 2
                Confidence = 84
                CorrelationHint = 'Unknown'
                FieldMap = [PSCustomObject]@{
                    Identity = @('Identity', 'DecoyIdentity', 'ElementId', 'TargetUserName', 'TargetIdentity')
                    Actor = @('SubjectUserName', 'UserName', 'AccountName', 'IpAddress')
                    ComputerName = @('Computer', 'ComputerName', 'WorkstationName', 'Host')
                    EvidenceRef = @('EventRecordId', 'RecordId', 'EventId', 'CaseId')
                    TokenIdentifier = @('TokenIdentifier', 'TokenFingerprint', 'TargetUserName')
                }
            }
            [PSCustomObject]@{
                PresetId = 'WindowsSecurity4663ObjectAccess'
                TriggerType = 'FileAccess'
                TriggerSource = 'WindowsSecurity:EventID4663'
                SignalCount = 2
                Confidence = 82
                CorrelationHint = 'Unknown'
                FieldMap = [PSCustomObject]@{
                    Identity = @('Identity', 'DecoyIdentity', 'ElementId', 'TargetIdentity', 'ObjectName')
                    Actor = @('SubjectUserName', 'UserName', 'AccountName', 'ProcessName')
                    ComputerName = @('Computer', 'ComputerName', 'Host', 'Hostname')
                    EvidenceRef = @('EventRecordId', 'RecordId', 'EventId', 'CaseId')
                    TokenIdentifier = @('TokenIdentifier', 'TokenFingerprint', 'ObjectName')
                }
            }
            [PSCustomObject]@{
                PresetId = 'WindowsSecurity4688ProcessCreate'
                TriggerType = 'ProcessAccess'
                TriggerSource = 'WindowsSecurity:EventID4688'
                SignalCount = 1
                Confidence = 74
                CorrelationHint = 'Unknown'
                FieldMap = [PSCustomObject]@{
                    Identity = @('Identity', 'DecoyIdentity', 'ElementId', 'TargetIdentity', 'NewProcessName')
                    Actor = @('SubjectUserName', 'UserName', 'AccountName', 'CommandLine')
                    ComputerName = @('Computer', 'ComputerName', 'Host', 'Hostname')
                    EvidenceRef = @('EventRecordId', 'RecordId', 'EventId', 'CaseId')
                    TokenIdentifier = @('TokenIdentifier', 'TokenFingerprint', 'CommandLine', 'NewProcessName')
                }
            }
        )
    }
}

function Get-PrivateF4keH0undTelemetryConnectorPack {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    $telemetrySettings = Get-F4keH0undConfig -Section 'TelemetrySettings'
    $moduleRoot = $PSScriptRoot | Split-Path -Parent

    $packPathRaw = if ($telemetrySettings -and $telemetrySettings.ConnectorPackPath) {
        [string]$telemetrySettings.ConnectorPackPath
    }
    else {
        './telemetry-connectors.windows.json'
    }

    $packPath = if ([System.IO.Path]::IsPathRooted($packPathRaw)) {
        $packPathRaw
    }
    else {
        Join-Path -Path $moduleRoot -ChildPath $packPathRaw
    }

    if (Test-Path -Path $packPath -PathType Leaf) {
        try {
            $pack = Get-Content -Path $packPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($pack -and $pack.Presets -and @($pack.Presets).Count -gt 0) {
                return $pack
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to parse telemetry connector pack '$packPath'. Falling back to built-in defaults."
        }
    }

    return Get-PrivateF4keH0undDefaultTelemetryConnectorPack
}

function Get-PrivateF4keH0undTelemetryConnectorPreset {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PresetId
    )

    if ([string]::IsNullOrWhiteSpace($PresetId)) {
        return $null
    }

    $pack = Get-PrivateF4keH0undTelemetryConnectorPack
    $match = @($pack.Presets | Where-Object { [string]$_.PresetId -eq [string]$PresetId } | Select-Object -First 1)
    if ($match.Count -eq 0) {
        return $null
    }

    return $match[0]
}

function Resolve-PrivateF4keH0undTelemetryPathValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Payload,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $current = $Payload
    foreach ($segment in @($Path.Split('.'))) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($null -eq $current) {
            return $null
        }

        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) {
                return $null
            }

            $current = $current[$segment]
            continue
        }

        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) {
            return $null
        }

        $current = $property.Value
    }

    return $current
}

function Get-PrivateF4keH0undTelemetryMappedValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Payload,

        [Parameter()]
        [string[]]$PathCandidates
    )

    foreach ($candidatePath in @($PathCandidates)) {
        $value = Resolve-PrivateF4keH0undTelemetryPathValue -Payload $Payload -Path ([string]$candidatePath)
        if ($null -eq $value) {
            continue
        }

        if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        return $value
    }

    return $null
}

function Convert-PrivateF4keH0undTelemetryPayloadToTriggerContext {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PresetId,

        [Parameter(Mandatory = $true)]
        [object]$Payload
    )

    $preset = Get-PrivateF4keH0undTelemetryConnectorPreset -PresetId $PresetId
    if ($null -eq $preset) {
        $pack = Get-PrivateF4keH0undTelemetryConnectorPack
        $availablePresets = @($pack.Presets | ForEach-Object { [string]$_.PresetId } | Sort-Object -Unique)
        $availableText = if ($availablePresets.Count -gt 0) {
            $availablePresets -join ', '
        }
        else {
            '<none>'
        }

        throw "Unknown ConnectorPreset '$PresetId'. Available presets: $availableText"
    }

    $fieldMap = Convert-PrivateF4keH0undTelemetryObjectToHashtable -InputObject $preset.FieldMap
    $resolvedIdentities = [System.Collections.Generic.List[string]]::new()

    foreach ($identityPath in @($fieldMap['Identity'])) {
        $identityCandidate = Resolve-PrivateF4keH0undTelemetryPathValue -Payload $Payload -Path ([string]$identityPath)
        foreach ($identityValue in @($identityCandidate)) {
            $identityText = [string]$identityValue
            if (-not [string]::IsNullOrWhiteSpace($identityText) -and -not $resolvedIdentities.Contains($identityText)) {
                $resolvedIdentities.Add($identityText)
            }
        }
    }

    $signalCount = [int]$preset.SignalCount
    $signalCandidate = Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @('SignalCount', 'SignalTotal')
    if ($null -ne $signalCandidate) {
        try {
            $parsedSignalCount = [int]$signalCandidate
            if ($parsedSignalCount -gt 0) {
                $signalCount = $parsedSignalCount
            }
        }
        catch {
            $signalCount = [int]$preset.SignalCount
        }
    }

    $confidence = [double]$preset.Confidence
    $confidenceCandidate = Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @('Confidence', 'ConfidenceScore')
    if ($null -ne $confidenceCandidate) {
        try {
            $parsedConfidence = [double]$confidenceCandidate
            if ($parsedConfidence -ge 0 -and $parsedConfidence -le 100) {
                $confidence = $parsedConfidence
            }
        }
        catch {
            $confidence = [double]$preset.Confidence
        }
    }

    $correlated = $false
    $correlationHintCandidate = [string](Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @('CorrelationHint', 'Correlated'))
    if (-not [string]::IsNullOrWhiteSpace($correlationHintCandidate)) {
        if ($correlationHintCandidate -match '^(?i:true|yes|correlated|1)$') {
            $correlated = $true
        }
    }
    elseif ([string]$preset.CorrelationHint -eq 'Correlated') {
        $correlated = $true
    }

    return [PSCustomObject]@{
        PresetId        = [string]$preset.PresetId
        Identity        = @($resolvedIdentities)
        TriggerType     = [string]$preset.TriggerType
        TriggerSource   = [string]$preset.TriggerSource
        Actor           = [string](Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @($fieldMap['Actor']))
        ComputerName    = [string](Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @($fieldMap['ComputerName']))
        EvidenceRef     = [string](Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @($fieldMap['EvidenceRef']))
        TokenIdentifier = [string](Get-PrivateF4keH0undTelemetryMappedValue -Payload $Payload -PathCandidates @($fieldMap['TokenIdentifier']))
        SignalCount     = $signalCount
        Confidence      = $confidence
        Correlated      = $correlated
    }
}
