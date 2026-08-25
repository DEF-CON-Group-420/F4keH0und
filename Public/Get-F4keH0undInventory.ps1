<#
.SYNOPSIS
    Displays a consolidated inventory view of deployed deceptive elements.

.DESCRIPTION
    Reads one or more F4keH0und deployment report CSV files and builds a normalized
    inventory containing identity, element type, deployment strategy, and current status.

    By default, the command reads only the latest deployment report from the configured
    ReportOutputPath and attempts live AD status verification for AD-backed elements.

.PARAMETER ReportPath
    Optional path to a specific deployment report CSV file.

.PARAMETER ReportDirectory
    Optional directory containing deployment report CSV files.
    If not specified, uses DeploymentSettings.ReportOutputPath from config.

.PARAMETER AllReports
    If set, reads all matching report files in the target report directory.
    Otherwise, only the most recent report is read.

.PARAMETER SkipLiveStatus
    If set, skips live status checks against AD and returns recorded inventory only.

.PARAMETER Server
    Optional Domain Controller for AD status checks.

.PARAMETER Credential
    Optional privileged credential for AD status checks.

.EXAMPLE
    Get-F4keH0undInventory

    Loads the latest deployment report from the configured report path and returns
    inventory with live AD status checks when possible.

.EXAMPLE
    Get-F4keH0undInventory -AllReports -SkipLiveStatus | Format-Table -AutoSize

    Combines all historical reports into a single inventory and skips live lookups.

.EXAMPLE
    Get-F4keH0undInventory -Server "DC01.target.local" -Credential (Get-Credential)

    Verifies current AD state against a specific domain controller.
#>
function Get-F4keH0undInventory {
    [CmdletBinding()]
    param(
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
        [System.Management.Automation.PSCredential]$Credential
    )

    $reportFiles = @()

    if ($PSBoundParameters.ContainsKey('ReportPath')) {
        if (-not (Test-Path -Path $ReportPath -PathType Leaf)) {
            Write-Error "[$($MyInvocation.MyCommand)] - Report file not found: $ReportPath"
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
            Write-Warning "[$($MyInvocation.MyCommand)] - Report directory not found: $ReportDirectory"
            return @()
        }

        $reportFiles = @(Get-ChildItem -Path $ReportDirectory -Filter 'F4keH0und*Report*.csv' -File |
            Sort-Object -Property LastWriteTime -Descending)

        if (-not $reportFiles) {
            Write-Warning "[$($MyInvocation.MyCommand)] - No deployment report files were found in '$ReportDirectory'."
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
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to parse report '$($reportFile.FullName)': $($_.Exception.Message)"
        }
    }

    if ($reportRows.Count -eq 0) {
        Write-Warning "[$($MyInvocation.MyCommand)] - No readable deployment rows were found."
        return @()
    }

    $adStatusParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $adStatusParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $adStatusParams['Credential'] = $Credential }

    $canQueryAdUsers = $null -ne (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)
    $canQueryAdComputers = $null -ne (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue)
    $canQueryAdGroups = $null -ne (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue)

    $inventoryRows = foreach ($reportRow in $reportRows) {
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
            'ACLAttackPath' {
                $objectType = 'User'
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

        $status = 'Recorded'

        if (-not $SkipLiveStatus) {
            if ($platform -eq 'AD') {
                $lookupParams = $adStatusParams.Clone()
                $lookupParams['Identity'] = $identity
                $lookupParams['ErrorAction'] = 'Stop'

                try {
                    switch ($objectType) {
                        'User' {
                            if (-not $canQueryAdUsers) {
                                $status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adUser = Get-ADUser @lookupParams -Properties Enabled, DistinguishedName
                                $status = if ($adUser.Enabled) { 'Enabled' } else { 'Disabled' }
                                $location = $adUser.DistinguishedName
                            }
                        }
                        'Computer' {
                            if (-not $canQueryAdComputers) {
                                $status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adComputer = Get-ADComputer @lookupParams -Properties Enabled, DistinguishedName
                                $status = if ($adComputer.Enabled) { 'Enabled' } else { 'Disabled' }
                                $location = $adComputer.DistinguishedName
                            }
                        }
                        'Group' {
                            if (-not $canQueryAdGroups) {
                                $status = 'Unverified (AD module unavailable)'
                            }
                            else {
                                $adGroup = Get-ADGroup @lookupParams -Properties DistinguishedName
                                $status = 'Present'
                                $location = $adGroup.DistinguishedName
                            }
                        }
                    }
                }
                catch {
                    $status = 'NotFound'
                }
            }
            else {
                $status = 'Recorded (Entra live check pending)'
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
            Identity         = $identity
            DecoyType        = $decoyType
            Strategy         = [string]$reportRow.Strategy
            Platform         = $platform
            ObjectType       = $objectType
            Status           = $status
            Location         = $location
            DeployedAt       = $deployedAt
            RIDAnomalySafe   = [string]$reportRow.RIDAnomalySafe
            ReportSource     = [IO.Path]::GetFileName([string]$reportRow._ReportSource)
            LastStatusCheck  = Get-Date
        }
    }

    return @($inventoryRows | Sort-Object -Property @{Expression = 'DeployedAt'; Descending = $true}, Identity)
}
