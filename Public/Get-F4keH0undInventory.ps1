<#
.SYNOPSIS
    Displays a consolidated inventory view of deployed deceptive elements.

.DESCRIPTION
    Reads inventory from the persistent inventory backend (event log + optional snapshot)
    and/or deployment report CSV files, then returns a normalized view containing identity,
    decoy type, deployment strategy, current status, and deployment location.

.PARAMETER Source
    Controls where inventory is read from:
      - Auto    : Prefer persistent inventory when available, otherwise fall back to reports.
      - Events  : Use persistent inventory backend only.
      - Reports : Use deployment report CSV files only.

.PARAMETER IncludeRemoved
    Events source only. Includes decoys with lifecycle state Removed.

.PARAMETER PreferSnapshot
    Events source only. When set, attempts to read the persisted snapshot first and falls
    back to event-log replay when snapshot is unavailable.

.PARAMETER ReportPath
    Reports source only. Optional path to a specific deployment report CSV file.

.PARAMETER ReportDirectory
    Reports source only. Optional directory containing deployment report CSV files.
    If not specified, uses DeploymentSettings.ReportOutputPath from config.

.PARAMETER AllReports
    Reports source only. If set, reads all matching report files in the target report
    directory. Otherwise, only the most recent report is read.

.PARAMETER SkipLiveStatus
    If set, skips live status checks against AD and returns recorded inventory only.

.PARAMETER Server
    Optional Domain Controller for AD status checks.

.PARAMETER Credential
    Optional privileged credential for AD status checks.

.PARAMETER Platform
    Optional platform filter after inventory load. Supported values: AD, Entra,
    Windows.

.PARAMETER ElementType
    Optional decoy/element type filter using `DecoyType` values.

.PARAMETER ElementFamily
    Optional element family filter from inventory metadata (for example,
    ServiceLure, RpcBait, ApiHookBait, RuntimeArtifact).

.PARAMETER ComputerName
    Optional host filter from inventory metadata (`ComputerName` or `TargetHost`).

.PARAMETER Status
    Optional status filter (for example, Armed, Disabled, Removed, Enabled,
    Recorded).

.EXAMPLE
    Get-F4keH0undInventory

    Returns inventory using the preferred source (persistent backend when available).

.EXAMPLE
    Get-F4keH0undInventory -Source Events -IncludeRemoved -PreferSnapshot

    Returns full lifecycle state from persistent inventory, including removed elements.

.EXAMPLE
    Get-F4keH0undInventory -Source Reports -AllReports -SkipLiveStatus | Format-Table -AutoSize

    Combines all historical report files and skips live lookups.

.EXAMPLE
    Get-F4keH0undInventory -Source Events -Platform Windows -ElementFamily ApiHookBait -Status Armed

    Returns active Windows artifact elements for one family.
#>
function Get-F4keH0undInventory {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Auto', 'Events', 'Reports')]
        [string]$Source = 'Auto',

        [Parameter()]
        [switch]$IncludeRemoved,

        [Parameter()]
        [switch]$PreferSnapshot,

        [Parameter()]
        [string]$ReportPath,

        [Parameter()]
        [string]$ReportDirectory,

        [Parameter()]
        [switch]$AllReports,

        [Parameter()]
        [switch]$SkipLiveStatus,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('AD', 'Entra', 'Windows')]
        [string]$Platform,

        [Parameter()]
        [string[]]$ElementType,

        [Parameter()]
        [string[]]$ElementFamily,

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string[]]$Status
    )

    $commandName = $MyInvocation.MyCommand.Name

    $ConvertReportRowsToInventory = {
        param(
            [Parameter(Mandatory = $true)]
            [System.Object[]]$Rows
        )

        foreach ($reportRow in $Rows) {
            $decoyType = [string]$reportRow.DecoyType
            $identity = [string]$reportRow.Identity
            $location = [string]$reportRow.DistinguishedName

            $platform = 'AD'
            $objectType = 'User'

            switch -Wildcard ($decoyType) {
                'UnconstrainedDelegationComputer' {
                    $objectType = 'Computer'
                    break
                }
                'Entra*Guest*' {
                    $platform = 'Entra'
                    $objectType = 'GuestUser'
                    break
                }
                'Entra*ServicePrincipal*' {
                    $platform = 'Entra'
                    $objectType = 'ServicePrincipal'
                    break
                }
                'Entra*AppRegistration*' {
                    $platform = 'Entra'
                    $objectType = 'AppRegistration'
                    break
                }
                default {
                    $objectType = 'User'
                }
            }

            $deployedAt = $null
            if ($reportRow.Timestamp) {
                try {
                    $deployedAt = [datetime]::Parse($reportRow.Timestamp)
                }
                catch {
                    $deployedAt = $null
                }
            }

            [PSCustomObject]@{
                Identity        = $identity
                DecoyType       = $decoyType
                Strategy        = [string]$reportRow.Strategy
                Platform        = $platform
                ObjectType      = $objectType
                Status          = 'Recorded'
                Location        = $location
                DeployedAt      = $deployedAt
                LastUpdated     = $deployedAt
                LastAction      = 'Deploy'
                IsActive        = $true
                RIDAnomalySafe  = [string]$reportRow.RIDAnomalySafe
                EventCount      = 1
                Metadata        = @{}
                ReportSource    = [IO.Path]::GetFileName([string]$reportRow._ReportSource)
                LastStatusCheck = $null
            }
        }
    }

    $GetReportRows = {
        $reportFiles = @()

        if ($PSBoundParameters.ContainsKey('ReportPath')) {
            if (-not (Test-Path -Path $ReportPath -PathType Leaf)) {
                Write-Error "[$commandName] - Report file not found: $ReportPath"
                return @()
            }

            $reportFiles = @(Get-Item -Path $ReportPath -ErrorAction Stop)
        }
        else {
            if (-not $PSBoundParameters.ContainsKey('ReportDirectory')) {
                $deploymentConfig = Get-F4keH0undConfig -Section 'DeploymentSettings'
                if ($deploymentConfig.ReportOutputPath) {
                    $ReportDirectory = $deploymentConfig.ReportOutputPath
                }
                else {
                    $ReportDirectory = Join-Path -Path $PWD -ChildPath 'reports'
                }
            }

            if (-not (Test-Path -Path $ReportDirectory -PathType Container)) {
                Write-Warning "[$commandName] - Report directory not found: $ReportDirectory"
                return @()
            }

            $reportFiles = @(Get-ChildItem -Path $ReportDirectory -Filter 'F4keH0und*Report*.csv' -File |
                Sort-Object -Property LastWriteTime -Descending)

            if (-not $reportFiles) {
                Write-Warning "[$commandName] - No deployment report files were found in '$ReportDirectory'."
                return @()
            }

            if (-not $AllReports) {
                $reportFiles = @($reportFiles | Select-Object -First 1)
            }
        }

        $reportRows = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($reportFile in $reportFiles) {
            try {
                $rowsFromFile = Import-Csv -Path $reportFile.FullName -ErrorAction Stop
                foreach ($row in $rowsFromFile) {
                    $row | Add-Member -NotePropertyName '_ReportSource' -NotePropertyValue $reportFile.FullName -Force
                    $reportRows.Add($row)
                }
            }
            catch {
                Write-Warning "[$commandName] - Failed to parse report '$($reportFile.FullName)': $($_.Exception.Message)"
            }
        }

        return @($reportRows)
    }

    $inventoryRows = @()
    $effectiveSource = $Source

    $store = Get-F4keH0undInventoryStore
    if ($effectiveSource -eq 'Auto' -and $store.PreferredSource -in @('Events', 'Reports')) {
        $effectiveSource = $store.PreferredSource
    }

    if ($effectiveSource -eq 'Auto') {
        if ($store.Enabled -and (Test-Path -Path $store.EventLogPath -PathType Leaf) -and
            ((Get-Item -Path $store.EventLogPath).Length -gt 0)) {
            $effectiveSource = 'Events'
        }
        else {
            $effectiveSource = 'Reports'
        }
    }

    if ($effectiveSource -eq 'Events') {
        $inventoryRows = @(Get-F4keH0undInventoryState -IncludeRemoved:$IncludeRemoved -PreferSnapshot:$PreferSnapshot)
        if (-not $inventoryRows) {
            if ($Source -eq 'Auto') {
                Write-Verbose "[$($MyInvocation.MyCommand)] - No persistent inventory records found; falling back to reports."
                $effectiveSource = 'Reports'
            }
            else {
                Write-Warning "[$($MyInvocation.MyCommand)] - No persistent inventory records were found."
                return @()
            }
        }
    }

    if ($effectiveSource -eq 'Reports') {
        $reportRows = @(& $GetReportRows)
        if (-not $reportRows) {
            return @()
        }

        $inventoryRows = @(& $ConvertReportRowsToInventory -Rows $reportRows)
        if (-not $inventoryRows) {
            Write-Warning "[$($MyInvocation.MyCommand)] - No readable deployment rows were found."
            return @()
        }
    }

    if (-not $SkipLiveStatus) {
        $adStatusParams = @{}
        if ($PSBoundParameters.ContainsKey('Server')) { $adStatusParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $adStatusParams['Credential'] = $Credential }

        $canQueryAdUsers = $null -ne (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)
        $canQueryAdComputers = $null -ne (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue)
        $canQueryAdGroups = $null -ne (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue)

        foreach ($row in $inventoryRows) {
            if ($row.Platform -eq 'AD') {
                $lookupParams = $adStatusParams.Clone()
                $lookupParams['Identity'] = $row.Identity
                $lookupParams['ErrorAction'] = 'Stop'

                try {
                    switch ($row.ObjectType) {
                        'User' {
                            if (-not $canQueryAdUsers) {
                                $row.Status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adUser = Get-ADUser @lookupParams -Properties Enabled, DistinguishedName
                                $row.Status = if ($adUser.Enabled) { 'Enabled' } else { 'Disabled' }
                                $row.Location = $adUser.DistinguishedName
                            }
                        }
                        'Computer' {
                            if (-not $canQueryAdComputers) {
                                $row.Status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adComputer = Get-ADComputer @lookupParams -Properties Enabled, DistinguishedName
                                $row.Status = if ($adComputer.Enabled) { 'Enabled' } else { 'Disabled' }
                                $row.Location = $adComputer.DistinguishedName
                            }
                        }
                        'Group' {
                            if (-not $canQueryAdGroups) {
                                $row.Status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adGroup = Get-ADGroup @lookupParams -Properties DistinguishedName
                                $row.Status = 'Present'
                                $row.Location = $adGroup.DistinguishedName
                            }
                        }
                        default {
                            $row.Status = 'Recorded'
                        }
                    }
                }
                catch {
                    $row.Status = 'NotFound'
                }
            }
            elseif ($row.Platform -eq 'Entra' -and [string]::IsNullOrWhiteSpace([string]$row.Status)) {
                $row.Status = 'Recorded (Entra live check pending)'
            }

            $row.LastStatusCheck = Get-Date
        }
    }

    if ($PSBoundParameters.ContainsKey('Platform')) {
        $inventoryRows = @($inventoryRows | Where-Object { [string]$_.Platform -eq $Platform })
    }

    if ($PSBoundParameters.ContainsKey('ElementType') -and @($ElementType).Count -gt 0) {
        $inventoryRows = @($inventoryRows | Where-Object { @($ElementType) -contains [string]$_.DecoyType })
    }

    if ($PSBoundParameters.ContainsKey('ElementFamily') -and @($ElementFamily).Count -gt 0) {
        $inventoryRows = @(
            $inventoryRows | Where-Object {
                $rowMetadata = Convert-PrivateF4keH0undObjectToHashtable -InputObject $_.Metadata
                if ($rowMetadata.ContainsKey('ElementFamily')) {
                    @($ElementFamily) -contains [string]$rowMetadata['ElementFamily']
                }
                else {
                    $false
                }
            }
        )
    }

    if ($PSBoundParameters.ContainsKey('ComputerName') -and @($ComputerName).Count -gt 0) {
        $inventoryRows = @(
            $inventoryRows | Where-Object {
                $rowMetadata = Convert-PrivateF4keH0undObjectToHashtable -InputObject $_.Metadata
                $rowHost = if ($rowMetadata.ContainsKey('ComputerName')) {
                    [string]$rowMetadata['ComputerName']
                }
                elseif ($rowMetadata.ContainsKey('TargetHost')) {
                    [string]$rowMetadata['TargetHost']
                }
                else {
                    $null
                }

                if ([string]::IsNullOrWhiteSpace($rowHost)) {
                    $false
                }
                else {
                    @($ComputerName) -contains $rowHost
                }
            }
        )
    }

    if ($PSBoundParameters.ContainsKey('Status') -and @($Status).Count -gt 0) {
        $inventoryRows = @($inventoryRows | Where-Object { @($Status) -contains [string]$_.Status })
    }

    return @($inventoryRows | Sort-Object -Property @{
        Expression = {
            if ($_.LastUpdated) {
                [datetime]$_.LastUpdated
            }
            elseif ($_.DeployedAt) {
                [datetime]$_.DeployedAt
            }
            else {
                [datetime]::MinValue
            }
        }
        Descending = $true
    }, @{
        Expression = { $_.Identity }
    })
}
