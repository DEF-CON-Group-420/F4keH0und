function Get-F4keH0undInventoryStore {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Ensure
    )

    $inventoryConfig = Get-F4keH0undConfig -Section 'InventorySettings'
    if ($null -eq $inventoryConfig) {
        $inventoryConfig = (Get-F4keH0undDefaultConfig).InventorySettings
    }

    $moduleRoot = $PSScriptRoot | Split-Path -Parent

    $inventoryDirectoryRaw = if ($inventoryConfig.InventoryDirectory) {
        [string]$inventoryConfig.InventoryDirectory
    }
    else {
        './inventory'
    }

    $inventoryDirectory = if ([System.IO.Path]::IsPathRooted($inventoryDirectoryRaw)) {
        $inventoryDirectoryRaw
    }
    else {
        Join-Path -Path $moduleRoot -ChildPath $inventoryDirectoryRaw
    }

    if ($Ensure -and -not (Test-Path -Path $inventoryDirectory)) {
        New-Item -Path $inventoryDirectory -ItemType Directory -Force | Out-Null
    }

    $eventLogFileName = if ($inventoryConfig.EventLogFileName) {
        [string]$inventoryConfig.EventLogFileName
    }
    else {
        'F4keH0und_Inventory_Events.ndjson'
    }

    $snapshotFileName = if ($inventoryConfig.SnapshotFileName) {
        [string]$inventoryConfig.SnapshotFileName
    }
    else {
        'F4keH0und_Inventory_Snapshot.json'
    }

    [PSCustomObject]@{
        Enabled               = [bool]$inventoryConfig.EnablePersistentInventory
        PreferredSource       = if ($inventoryConfig.PreferredSource) { [string]$inventoryConfig.PreferredSource } else { 'Auto' }
        UpdateSnapshotOnWrite = if ($null -ne $inventoryConfig.UpdateSnapshotOnWrite) { [bool]$inventoryConfig.UpdateSnapshotOnWrite } else { $true }
        InventoryDirectory    = $inventoryDirectory
        EventLogPath          = Join-Path -Path $inventoryDirectory -ChildPath $eventLogFileName
        SnapshotPath          = Join-Path -Path $inventoryDirectory -ChildPath $snapshotFileName
    }
}

function Get-F4keH0undInventoryEvents {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [string]$Path
    )

    if (-not $PSBoundParameters.ContainsKey('Path')) {
        $store = Get-F4keH0undInventoryStore
        $Path = $store.EventLogPath
    }

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return @()
    }

    $events = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($line in (Get-Content -Path $Path -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        try {
            $events.Add(($line | ConvertFrom-Json -ErrorAction Stop))
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Skipping malformed inventory event line in '$Path'."
        }
    }

    return @($events | Sort-Object @{
        Expression = {
            try {
                [datetime]$_.timestamp
            }
            catch {
                [datetime]::MinValue
            }
        }
    }, @{
        Expression = { $_.eventId }
    })
}

function Convert-PrivateF4keH0undInventoryObjectToHashtable {
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

function Get-PrivateF4keH0undTokenFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    if ($Value -match '^sha256:[a-fA-F0-9]{16,64}$') {
        return $Value.ToLowerInvariant()
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.Trim())
        $hashBytes = $sha256.ComputeHash($bytes)
        $hex = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        return "sha256:$($hex.Substring(0, 16))"
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-PrivateF4keH0undTokenCorrelationContext {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter()]
        [hashtable]$Metadata
    )

    $fingerprints = [System.Collections.Generic.List[string]]::new()
    $tokenKeys = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Metadata) {
        return [PSCustomObject]@{
            TokenFingerprints = @()
            TokenKeys         = @()
        }
    }

    if ($Metadata.ContainsKey('TokenFingerprints')) {
        foreach ($fingerprint in @($Metadata['TokenFingerprints'])) {
            $value = [string]$fingerprint
            if (-not [string]::IsNullOrWhiteSpace($value) -and -not $fingerprints.Contains($value)) {
                $fingerprints.Add($value)
            }
        }
    }

    $candidateValues = [System.Collections.Generic.List[string]]::new()
    $tokenLikePattern = '(?i)token|secret|password|key|credential'

    $templateData = @{}
    if ($Metadata.ContainsKey('TemplateData')) {
        $templateData = Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $Metadata['TemplateData']
    }

    foreach ($templateKey in $templateData.Keys) {
        $keyName = [string]$templateKey
        if ($keyName -match $tokenLikePattern) {
            if (-not $tokenKeys.Contains($keyName)) {
                $tokenKeys.Add($keyName)
            }

            $value = [string]$templateData[$templateKey]
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $candidateValues.Add($value)
            }
        }
    }

    foreach ($metadataKey in $Metadata.Keys) {
        $keyName = [string]$metadataKey
        if ($keyName -match $tokenLikePattern -or $keyName -eq 'TokenIdentifier') {
            if (-not $tokenKeys.Contains($keyName)) {
                $tokenKeys.Add($keyName)
            }

            $value = [string]$Metadata[$metadataKey]
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $candidateValues.Add($value)
            }
        }
    }

    foreach ($candidateValue in $candidateValues) {
        $fingerprint = Get-PrivateF4keH0undTokenFingerprint -Value $candidateValue
        if (-not [string]::IsNullOrWhiteSpace($fingerprint) -and -not $fingerprints.Contains($fingerprint)) {
            $fingerprints.Add($fingerprint)
        }
    }

    return [PSCustomObject]@{
        TokenFingerprints = @($fingerprints)
        TokenKeys         = @($tokenKeys)
    }
}

function Get-PrivateF4keH0undAlertAssessment {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Entry
    )

    $triggerCount = [int]$Entry.TriggerCount
    if ($triggerCount -le 0) {
        return [PSCustomObject]@{
            Score    = 0
            Severity = 'None'
            Reasons  = @()
        }
    }

    $score = 20
    $reasons = [System.Collections.Generic.List[string]]::new()
    $reasons.Add("Trigger events observed: $triggerCount")

    $signalCount = [int]$Entry.TriggerSignalCount
    if ($signalCount -gt 0) {
        $signalContribution = [Math]::Min(30, $signalCount * 5)
        $score += $signalContribution
        $reasons.Add("Signal count contribution: +$signalContribution")
    }

    $repeatContribution = [Math]::Min(15, [Math]::Max(0, ($triggerCount - 1) * 3))
    if ($repeatContribution -gt 0) {
        $score += $repeatContribution
        $reasons.Add("Repeated trigger contribution: +$repeatContribution")
    }

    $confidence = 0
    try {
        $confidence = [double]$Entry.LastTriggerConfidence
    }
    catch {
        $confidence = 0
    }

    if ($confidence -gt 0) {
        $confidenceContribution = [Math]::Min(20, [Math]::Round($confidence / 5, 0))
        $score += $confidenceContribution
        $reasons.Add("Confidence contribution: +$confidenceContribution")
    }

    $correlationStatus = [string]$Entry.TokenCorrelationStatus
    switch ($correlationStatus) {
        'Correlated' {
            $score += 15
            $reasons.Add('Token correlation matched known canary fingerprint: +15')
        }
        'Uncorrelated' {
            $score -= 15
            $reasons.Add('Token correlation mismatch penalty: -15')
        }
    }

    $decoyType = [string]$Entry.DecoyType
    if ($decoyType -match '(?i)token|credential|apihook|identity') {
        $score += 10
        $reasons.Add('Identity/token decoy family priority boost: +10')
    }

    if ([string]$Entry.Strategy -eq 'Artifact') {
        $score += 5
        $reasons.Add('Artifact strategy operational confidence: +5')
    }

    if ([string]$Entry.Status -eq 'Removed') {
        $score -= 30
        $reasons.Add('Removed element penalty: -30')
    }

    $score = [Math]::Max(0, [Math]::Min(100, [int][Math]::Round($score, 0)))
    $severity = if ($score -ge 85) {
        'Critical'
    }
    elseif ($score -ge 65) {
        'High'
    }
    elseif ($score -ge 40) {
        'Medium'
    }
    else {
        'Low'
    }

    return [PSCustomObject]@{
        Score    = $score
        Severity = $severity
        Reasons  = @($reasons)
    }
}

function Convert-F4keH0undInventoryEventsToState {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Object[]]$Events,

        [Parameter()]
        [switch]$IncludeRemoved
    )

    $stateByKey = @{}

    foreach ($event in $Events) {
        $identity = [string]$event.identity
        if ([string]::IsNullOrWhiteSpace($identity)) {
            continue
        }

        $platform = if ([string]::IsNullOrWhiteSpace([string]$event.platform)) { 'AD' } else { [string]$event.platform }
        $decoyType = if ([string]::IsNullOrWhiteSpace([string]$event.decoyType)) { 'UnknownDecoy' } else { [string]$event.decoyType }
        $objectType = if ([string]::IsNullOrWhiteSpace([string]$event.objectType)) { 'User' } else { [string]$event.objectType }
        $key = "$platform|$identity|$decoyType|$objectType"

        if (-not $stateByKey.ContainsKey($key)) {
            $stateByKey[$key] = [PSCustomObject]@{
                Identity        = $identity
                DecoyType       = $decoyType
                Strategy        = $null
                Platform        = $platform
                ObjectType      = $objectType
                Status          = 'Recorded'
                Location        = $null
                DeployedAt      = $null
                LastUpdated     = $null
                LastAction      = $null
                IsActive        = $true
                RIDAnomalySafe  = 'Unknown'
                EventCount      = 0
                Metadata        = @{}
                TriggerCount    = 0
                TriggerSignalCount = 0
                FirstTriggeredAt = $null
                LastTriggeredAt = $null
                LastTriggerType = $null
                LastTriggerSource = $null
                LastTriggerActor = $null
                LastTriggerEvidence = $null
                LastTriggerConfidence = 0
                TokenFingerprints = @()
                TokenKeys       = @()
                TokenCorrelationStatus = 'Unknown'
                TokenCorrelationMatched = $false
                AlertScore      = 0
                AlertSeverity   = 'None'
                AlertReasons    = @()
                ReportSource    = 'InventoryEvents'
                LastStatusCheck = $null
            }
        }

        $entry = $stateByKey[$key]

        $eventTime = $null
        if ($event.timestamp) {
            try {
                $eventTime = [datetime]$event.timestamp
            }
            catch {
                $eventTime = $null
            }
        }
        if ($null -eq $eventTime) {
            $eventTime = Get-Date
        }

        $entry.EventCount = [int]$entry.EventCount + 1
        $entry.LastUpdated = $eventTime
        $entry.LastAction = [string]$event.action

        if (-not [string]::IsNullOrWhiteSpace([string]$event.strategy)) {
            $entry.Strategy = [string]$event.strategy
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$event.location)) {
            $entry.Location = [string]$event.location
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$event.status)) {
            $entry.Status = [string]$event.status
        }

        if ($null -eq $entry.DeployedAt -and [string]$event.action -eq 'Deploy') {
            $entry.DeployedAt = $eventTime
        }

        if ($event.metadata) {
            $existingMetadata = Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $entry.Metadata
            $eventMetadata = Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $event.metadata
            foreach ($metadataKey in $eventMetadata.Keys) {
                $existingMetadata[$metadataKey] = $eventMetadata[$metadataKey]
            }
            $entry.Metadata = $existingMetadata

            $tokenContext = Get-PrivateF4keH0undTokenCorrelationContext -Metadata $existingMetadata
            $entry.TokenFingerprints = @($tokenContext.TokenFingerprints)
            $entry.TokenKeys = @($tokenContext.TokenKeys)
        }

        switch ([string]$event.action) {
            'Deploy' {
                $entry.IsActive = $true
                if ([string]::IsNullOrWhiteSpace([string]$event.status)) {
                    $entry.Status = if ($entry.ObjectType -eq 'Group') { 'Present' } else { 'Enabled' }
                }
            }
            'Enable' {
                $entry.IsActive = $true
                if ([string]::IsNullOrWhiteSpace([string]$event.status)) {
                    $entry.Status = 'Enabled'
                }
            }
            'Disable' {
                $entry.IsActive = $true
                $entry.Status = 'Disabled'
            }
            'Remove' {
                $entry.IsActive = $false
                $entry.Status = 'Removed'
            }
            'Trigger' {
                $triggerMetadata = Convert-PrivateF4keH0undInventoryObjectToHashtable -InputObject $entry.Metadata
                $signalCount = 1
                if ($triggerMetadata.ContainsKey('SignalCount')) {
                    try {
                        $parsedSignalCount = [int]$triggerMetadata['SignalCount']
                        if ($parsedSignalCount -gt 0) {
                            $signalCount = $parsedSignalCount
                        }
                    }
                    catch {
                        $signalCount = 1
                    }
                }

                $entry.TriggerCount = [int]$entry.TriggerCount + 1
                $entry.TriggerSignalCount = [int]$entry.TriggerSignalCount + $signalCount

                if ($null -eq $entry.FirstTriggeredAt) {
                    $entry.FirstTriggeredAt = $eventTime
                }
                $entry.LastTriggeredAt = $eventTime

                if ($triggerMetadata.ContainsKey('TriggerType')) {
                    $entry.LastTriggerType = [string]$triggerMetadata['TriggerType']
                }
                if ($triggerMetadata.ContainsKey('TriggerSource')) {
                    $entry.LastTriggerSource = [string]$triggerMetadata['TriggerSource']
                }
                if ($triggerMetadata.ContainsKey('Actor')) {
                    $entry.LastTriggerActor = [string]$triggerMetadata['Actor']
                }
                if ($triggerMetadata.ContainsKey('EvidenceRef')) {
                    $entry.LastTriggerEvidence = [string]$triggerMetadata['EvidenceRef']
                }
                if ($triggerMetadata.ContainsKey('Confidence')) {
                    try {
                        $entry.LastTriggerConfidence = [double]$triggerMetadata['Confidence']
                    }
                    catch {
                        $entry.LastTriggerConfidence = 0
                    }
                }

                if ($entry.IsActive -ne $false) {
                    $entry.Status = 'Triggered'
                }

                $tokenIdentifier = if ($triggerMetadata.ContainsKey('TokenIdentifier')) {
                    [string]$triggerMetadata['TokenIdentifier']
                }
                else {
                    $null
                }

                if (-not [string]::IsNullOrWhiteSpace($tokenIdentifier)) {
                    $normalizedIdentifier = Get-PrivateF4keH0undTokenFingerprint -Value $tokenIdentifier
                    if ($normalizedIdentifier -and (@($entry.TokenFingerprints) -contains $normalizedIdentifier)) {
                        $entry.TokenCorrelationStatus = 'Correlated'
                        $entry.TokenCorrelationMatched = $true
                    }
                    else {
                        $entry.TokenCorrelationStatus = 'Uncorrelated'
                        $entry.TokenCorrelationMatched = $false
                    }
                }
                elseif ($triggerMetadata.ContainsKey('CorrelationHint') -and [string]$triggerMetadata['CorrelationHint'] -eq 'Correlated') {
                    $entry.TokenCorrelationStatus = 'Correlated'
                    $entry.TokenCorrelationMatched = $true
                }
                else {
                    $entry.TokenCorrelationStatus = 'Unknown'
                }
            }
        }

        if ($entry.Strategy -eq 'Recycle') {
            $entry.RIDAnomalySafe = 'Yes'
        }
        elseif ($entry.Strategy -eq 'Create') {
            $entry.RIDAnomalySafe = 'No'
        }

        $assessment = Get-PrivateF4keH0undAlertAssessment -Entry $entry
        $entry.AlertScore = [int]$assessment.Score
        $entry.AlertSeverity = [string]$assessment.Severity
        $entry.AlertReasons = @($assessment.Reasons)
    }

    $state = @($stateByKey.Values)
    if (-not $IncludeRemoved) {
        $state = @($state | Where-Object { $_.IsActive -ne $false })
    }

    return @($state | Sort-Object -Property @{ Expression = 'LastUpdated'; Descending = $true }, Identity)
}

function Get-F4keH0undInventoryState {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [switch]$IncludeRemoved,

        [Parameter()]
        [switch]$PreferSnapshot
    )

    $store = Get-F4keH0undInventoryStore

    if ($PreferSnapshot -and (Test-Path -Path $store.SnapshotPath -PathType Leaf)) {
        try {
            $snapshot = Get-Content -Path $store.SnapshotPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $snapshotRows = @($snapshot)
            if (-not $IncludeRemoved) {
                $snapshotRows = @($snapshotRows | Where-Object { $_.IsActive -ne $false })
            }

            return @($snapshotRows | Sort-Object -Property @{ Expression = 'LastUpdated'; Descending = $true }, Identity)
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to load inventory snapshot at '$($store.SnapshotPath)'. Falling back to event log."
        }
    }

    $events = Get-F4keH0undInventoryEvents -Path $store.EventLogPath
    if (-not $events) {
        return @()
    }

    return Convert-F4keH0undInventoryEventsToState -Events $events -IncludeRemoved:$IncludeRemoved
}

function Write-F4keH0undInventoryEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Deploy', 'Update', 'Disable', 'Enable', 'Remove', 'Trigger')]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter()]
        [string]$DecoyType = 'UnknownDecoy',

        [Parameter()]
        [string]$Platform = 'AD',

        [Parameter()]
        [string]$ObjectType = 'User',

        [Parameter()]
        [string]$Strategy,

        [Parameter()]
        [string]$Status,

        [Parameter()]
        [string]$Location,

        [Parameter()]
        [hashtable]$Metadata = @{},

        [Parameter()]
        [string]$SourceCommand
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        Write-Warning "[$($MyInvocation.MyCommand)] - Identity is empty; inventory event was not written."
        return
    }

    $store = Get-F4keH0undInventoryStore -Ensure
    if (-not $store.Enabled) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($Status) -and $Action -eq 'Trigger') {
        $Status = 'Triggered'
    }

    $entry = [ordered]@{
        timestamp     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        eventId       = [guid]::NewGuid().ToString()
        action        = $Action
        identity      = $Identity
        decoyType     = $DecoyType
        platform      = $Platform
        objectType    = $ObjectType
        strategy      = $Strategy
        status        = $Status
        location      = $Location
        metadata      = $Metadata
        sourceCommand = if ([string]::IsNullOrWhiteSpace($SourceCommand)) { $MyInvocation.MyCommand.Name } else { $SourceCommand }
    }

    try {
        $line = $entry | ConvertTo-Json -Compress -Depth 8
        Add-Content -Path $store.EventLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "[$($MyInvocation.MyCommand)] - Inventory event written to '$($store.EventLogPath)' (Action: $Action, Identity: $Identity)."

        if ($store.UpdateSnapshotOnWrite) {
            $snapshot = Get-F4keH0undInventoryState -IncludeRemoved
            $snapshotJson = $snapshot | ConvertTo-Json -Depth 8
            Set-Content -Path $store.SnapshotPath -Value $snapshotJson -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to write inventory event. Error: $($_.Exception.Message)"
    }
}
