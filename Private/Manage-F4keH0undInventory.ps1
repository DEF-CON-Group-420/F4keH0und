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
            $metadataTable = @{}
            foreach ($property in $event.metadata.PSObject.Properties) {
                $metadataTable[$property.Name] = $property.Value
            }
            $entry.Metadata = $metadataTable
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
        }

        if ($entry.Strategy -eq 'Recycle') {
            $entry.RIDAnomalySafe = 'Yes'
        }
        elseif ($entry.Strategy -eq 'Create') {
            $entry.RIDAnomalySafe = 'No'
        }
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
        [ValidateSet('Deploy', 'Update', 'Disable', 'Enable', 'Remove')]
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
