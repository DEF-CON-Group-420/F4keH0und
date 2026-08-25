<#
.SYNOPSIS
    Validates the F4keH0und configuration file.

.DESCRIPTION
    Checks the config.json file for common errors, missing required fields,
    and invalid values. Returns validation results with warnings and errors.

.PARAMETER ConfigPath
    Optional path to a custom configuration file. If not specified, uses the default
    config.json in the module root directory.

.EXAMPLE
    Test-F4keH0undConfig -Verbose

.EXAMPLE
    $validation = Test-F4keH0undConfig
    if ($validation.IsValid) {
        Write-Host "Configuration is valid"
    }
#>
function Test-F4keH0undConfig {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ConfigPath
    )

    $validationResult = [PSCustomObject]@{
        IsValid  = $true
        Warnings = @()
        Errors   = @()
    }

    # Determine config file path
    if (-not $PSBoundParameters.ContainsKey('ConfigPath')) {
        $moduleRoot = $PSScriptRoot | Split-Path -Parent
        $ConfigPath = Join-Path -Path $moduleRoot -ChildPath 'config.json'
    }

    # Check file exists
    if (-not (Test-Path -Path $ConfigPath)) {
        $validationResult.Errors += "Configuration file not found at '$ConfigPath'"
        $validationResult.IsValid = $false
        return $validationResult
    }

    # Try to load JSON
    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    }
    catch {
        $validationResult.Errors += "Failed to parse JSON: $($_.Exception.Message)"
        $validationResult.IsValid = $false
        return $validationResult
    }

    # Validate RecyclingPreferences
    if ($config.RecyclingPreferences.MinimumObjectAgeDays -ge $config.RecyclingPreferences.MaximumObjectAgeDays) {
        $validationResult.Errors += "MinimumObjectAgeDays must be less than MaximumObjectAgeDays"
        $validationResult.IsValid = $false
    }

    if ($config.RecyclingPreferences.MinimumObjectAgeDays -lt 90) {
        $validationResult.Warnings += "MinimumObjectAgeDays is less than 90 days. This may recycle objects that are too recent."
    }

    # Validate SafetyFilters
    if ($config.SafetyFilters.ProtectedUserPatterns.Count -eq 0) {
        $validationResult.Warnings += "No protected user patterns defined. This may allow recycling of critical accounts."
    }

    # Validate InventorySettings
    if ($config.PSObject.Properties.Name -contains 'InventorySettings') {
        $preferredSource = [string]$config.InventorySettings.PreferredSource
        if ($preferredSource -and $preferredSource -notin @('Auto', 'Events', 'Reports')) {
            $validationResult.Errors += "InventorySettings.PreferredSource must be one of: Auto, Events, Reports"
            $validationResult.IsValid = $false
        }

        if ($config.InventorySettings.EventLogFileName -and -not $config.InventorySettings.EventLogFileName.ToString().EndsWith('.ndjson')) {
            $validationResult.Warnings += "InventorySettings.EventLogFileName does not end with '.ndjson'. NDJSON is recommended for event logs."
        }
    }

    # Validate WindowsDeploymentSettings
    if ($config.PSObject.Properties.Name -contains 'WindowsDeploymentSettings') {
        $port = [int]$config.WindowsDeploymentSettings.Port
        if ($port -lt 1 -or $port -gt 65535) {
            $validationResult.Errors += "WindowsDeploymentSettings.Port must be between 1 and 65535"
            $validationResult.IsValid = $false
        }

        $auth = [string]$config.WindowsDeploymentSettings.Authentication
        if ($auth -and $auth -notin @('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')) {
            $validationResult.Errors += "WindowsDeploymentSettings.Authentication must be one of: Default, Negotiate, Kerberos, CredSSP, Basic"
            $validationResult.IsValid = $false
        }

        if ([string]::IsNullOrWhiteSpace([string]$config.WindowsDeploymentSettings.ArtifactRoot)) {
            $validationResult.Warnings += 'WindowsDeploymentSettings.ArtifactRoot is empty. Default artifact root will be used at runtime.'
        }
    }

    # Validate TelemetrySettings
    if ($config.PSObject.Properties.Name -contains 'TelemetrySettings') {
        if ([string]::IsNullOrWhiteSpace([string]$config.TelemetrySettings.DefaultTelemetryProfile)) {
            $validationResult.Warnings += 'TelemetrySettings.DefaultTelemetryProfile is empty. Runtime fallback profile will be used.'
        }

        $connectorPackPath = [string]$config.TelemetrySettings.ConnectorPackPath
        if (-not [string]::IsNullOrWhiteSpace($connectorPackPath)) {
            $resolvedConnectorPackPath = if ([System.IO.Path]::IsPathRooted($connectorPackPath)) {
                $connectorPackPath
            }
            else {
                $configDirectory = Split-Path -Path $ConfigPath -Parent
                Join-Path -Path $configDirectory -ChildPath $connectorPackPath
            }

            if (-not (Test-Path -Path $resolvedConnectorPackPath -PathType Leaf)) {
                $validationResult.Warnings += "Telemetry connector pack '$connectorPackPath' (resolved: '$resolvedConnectorPackPath') was not found locally. Built-in telemetry presets will be used."
            }
        }
    }

    # Validate ElementRegistrySettings
    if ($config.PSObject.Properties.Name -contains 'ElementRegistrySettings') {
        if ($config.ElementRegistrySettings.EnableExternalRegistry -eq $true) {
            $registryPath = [string]$config.ElementRegistrySettings.RegistryPath
            if ([string]::IsNullOrWhiteSpace($registryPath)) {
                $validationResult.Warnings += 'ElementRegistrySettings.RegistryPath is empty. Built-in defaults will be used.'
            }
            else {
                $resolvedRegistryPath = if ([System.IO.Path]::IsPathRooted($registryPath)) {
                    $registryPath
                }
                else {
                    $configDirectory = Split-Path -Path $ConfigPath -Parent
                    Join-Path -Path $configDirectory -ChildPath $registryPath
                }

                if (-not (Test-Path -Path $resolvedRegistryPath -PathType Leaf)) {
                    $validationResult.Warnings += "Element registry file '$registryPath' (resolved: '$resolvedRegistryPath') was not found locally. Built-in defaults will be used."
                }
            }
        }
    }

    # Validate paths exist or can be created
    $pathsToCheck = @(
        $config.DeploymentSettings.ReportOutputPath,
        $config.AuditSettings.AuditLogPath,
        $config.InventorySettings.InventoryDirectory
    )
    foreach ($path in $pathsToCheck) {
        if ($path -and -not (Test-Path $path)) {
            try {
                New-Item -Path $path -ItemType Directory -Force -WhatIf | Out-Null
            }
            catch {
                $validationResult.Warnings += "Cannot create directory '$path': $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Validation complete. IsValid: $($validationResult.IsValid), Warnings: $($validationResult.Warnings.Count), Errors: $($validationResult.Errors.Count)"

    return $validationResult
}
