<#
.SYNOPSIS
    Loads and validates the F4keH0und configuration from config.json.

.DESCRIPTION
    Reads the config.json file from the module root directory and returns a validated
    configuration object. If the file doesn't exist or is invalid, returns default values.

    Configuration values can be overridden by command-line parameters in calling functions.

.PARAMETER ConfigPath
    Optional path to a custom configuration file. If not specified, uses the default
    config.json in the module root directory.

.PARAMETER Section
    Optional. If specified, returns only the specified configuration section
    (e.g., 'RecyclingPreferences', 'SafetyFilters').

.EXAMPLE
    $config = Get-F4keH0undConfig
    $minAge = $config.RecyclingPreferences.MinimumObjectAgeDays

.EXAMPLE
    $safetyFilters = Get-F4keH0undConfig -Section 'SafetyFilters'
    $excludedOUs = $safetyFilters.ExcludedOUs

.EXAMPLE
    $config = Get-F4keH0undConfig -ConfigPath "C:\CustomConfig\f4keh0und.json"
#>
function Get-F4keH0undConfig {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [ValidateSet('RecyclingPreferences', 'SafetyFilters', 'DeploymentSettings', 'RankingWeights', 'AuditSettings', 'AdvancedOptions')]
        [string]$Section
    )

    # Determine config file path
    if (-not $PSBoundParameters.ContainsKey('ConfigPath')) {
        $moduleRoot = $PSScriptRoot | Split-Path -Parent
        $ConfigPath = Join-Path -Path $moduleRoot -ChildPath 'config.json'
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Loading configuration from: $ConfigPath"

    # Check if config file exists
    if (-not (Test-Path -Path $ConfigPath)) {
        Write-Warning "[$($MyInvocation.MyCommand)] - Configuration file not found at '$ConfigPath'. Using default values."
        return Get-F4keH0undDefaultConfig -Section $Section
    }

    # Load and parse JSON
    try {
        $configContent = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop

        Write-Verbose "[$($MyInvocation.MyCommand)] - Configuration loaded successfully"

        # Validate required sections exist
        $requiredSections = @('RecyclingPreferences', 'SafetyFilters', 'DeploymentSettings')
        foreach ($reqSection in $requiredSections) {
            if (-not $config.PSObject.Properties.Name.Contains($reqSection)) {
                Write-Warning "[$($MyInvocation.MyCommand)] - Missing required section '$reqSection'. Using defaults for this section."
                $defaults = Get-F4keH0undDefaultConfig
                $config | Add-Member -MemberType NoteProperty -Name $reqSection -Value $defaults.$reqSection -Force
            }
        }

        # Return specific section if requested
        if ($PSBoundParameters.ContainsKey('Section')) {
            if ($config.PSObject.Properties.Name.Contains($Section)) {
                return $config.$Section
            }
            else {
                Write-Warning "[$($MyInvocation.MyCommand)] - Section '$Section' not found in config. Returning defaults."
                return (Get-F4keH0undDefaultConfig).$Section
            }
        }

        return $config
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to load configuration from '$ConfigPath': $($_.Exception.Message)"
        Write-Warning "[$($MyInvocation.MyCommand)] - Falling back to default configuration."
        return Get-F4keH0undDefaultConfig -Section $Section
    }
}

<#
.SYNOPSIS
    Returns default F4keH0und configuration values.

.DESCRIPTION
    Provides hard-coded default configuration when config.json is missing or invalid.
    These defaults represent conservative, safe values suitable for most environments.
#>
function Get-F4keH0undDefaultConfig {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Section
    )

    $defaultConfig = [PSCustomObject]@{
        RecyclingPreferences = [PSCustomObject]@{
            PreferRecycling               = $true
            RecyclingOnly                 = $false
            MinimumObjectAgeDays          = 180
            MaximumObjectAgeDays          = 3650
            MaxRecyclableUsersPerScan     = 50
            MaxRecyclableComputersPerScan = 20
            MaxRecyclableGroupsPerScan    = 20
        }

        SafetyFilters = [PSCustomObject]@{
            ExcludedOUs = @(
                "OU=VIP,DC=*",
                "OU=Executives,DC=*",
                "OU=Domain Controllers,DC=*",
                "CN=Builtin,DC=*"
            )
            ProtectedUserPatterns = @(
                "^Administrator$", "^krbtgt$", "^Guest$",
                "^MSOL_", "^AAD_", "^AZUREADSSOACC"
            )
            ProtectedComputerPatterns = @(
                "^DC\\d*$", "^.*-DC-.*$", "^DNS.*$", "^EXCH.*$"
            )
            ProtectedGroupPatterns = @(
                "^Domain Admins$", "^Enterprise Admins$", "^.*Admins$"
            )
            RequireEmptyGroups           = $true
            AllowServiceAccountRecycling = $true
            MinimumPasswordAgeDays       = 180
            RequireDisabledAccounts      = $true
        }

        DeploymentSettings = [PSCustomObject]@{
            DefaultDecoyPrefix = ""
            DefaultDecoySuffix = ""
            AutoGenerateReport = $true
            ReportOutputPath   = "./reports"
            InteractiveMode    = $true
            VerboseLogging     = $false
            WhatIfByDefault    = $false
        }

        RankingWeights = [PSCustomObject]@{
            RecyclingRankBoost             = $true
            StalenessScoreWeight           = 0.4
            PrivilegedGroupProximityWeight = 0.3
            IsolationWeight                = 0.2
            AgeWeight                      = 0.1
        }

        AuditSettings = [PSCustomObject]@{
            EnableAuditLogging         = $true
            AuditLogPath               = "./audit"
            LogFormat                  = "JSON"
            IncludeOriginalObjectState = $true
            IncludeModificationDetails = $true
            IncludeRecyclingMetadata   = $true
        }

        AdvancedOptions = [PSCustomObject]@{
            EnableCrossForestRecycling = $false
            TrustedForests             = @()
            CacheRecyclableObjects     = $true
            CacheDurationMinutes       = 60
            ParallelDiscovery          = $false
            MaxParallelThreads         = 4
        }
    }

    if ($PSBoundParameters.ContainsKey('Section')) {
        return $defaultConfig.$Section
    }

    return $defaultConfig
}
