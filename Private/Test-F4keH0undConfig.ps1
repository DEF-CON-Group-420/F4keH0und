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

    # Validate paths exist or can be created
    $pathsToCheck = @($config.DeploymentSettings.ReportOutputPath, $config.AuditSettings.AuditLogPath)
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
