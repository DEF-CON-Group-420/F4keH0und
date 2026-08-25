function Get-PrivateF4keH0undElementRegistryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $registrySettings = Get-F4keH0undConfig -Section 'ElementRegistrySettings'
    $moduleRoot = $PSScriptRoot | Split-Path -Parent

    $registryPathRaw = if ($registrySettings.RegistryPath) {
        [string]$registrySettings.RegistryPath
    }
    else {
        './element-types.windows.json'
    }

    if ([System.IO.Path]::IsPathRooted($registryPathRaw)) {
        return $registryPathRaw
    }

    return Join-Path -Path $moduleRoot -ChildPath $registryPathRaw
}

function Get-PrivateF4keH0undDefaultElementTypeRegistry {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    $types = @(
        [PSCustomObject]@{
            TypeId          = 'ServiceDefinitionDecoy'
            Family          = 'ServiceLure'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 2
            DetectionScore  = 8
            TelemetryProfile = 'Windows-Artifact-Baseline'
            Description     = 'Deploys fake legacy service definitions and operational runbook artifacts.'
        }
        [PSCustomObject]@{
            TypeId          = 'RpcEndpointDecoy'
            Family          = 'RpcBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 2
            DetectionScore  = 7
            TelemetryProfile = 'Windows-Artifact-Baseline'
            Description     = 'Deploys fake RPC endpoint metadata and client connection profiles.'
        }
        [PSCustomObject]@{
            TypeId          = 'ApiHookConfigDecoy'
            Family          = 'ApiHookBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 9
            TelemetryProfile = 'Windows-Artifact-Baseline'
            Description     = 'Deploys fake integration configs, webhook references, and canary tokens.'
        }
        [PSCustomObject]@{
            TypeId          = 'ProcessThreadArtifactDecoy'
            Family          = 'RuntimeArtifact'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 6
            TelemetryProfile = 'Windows-Artifact-Baseline'
            Description     = 'Deploys fake process/thread troubleshooting artifacts and notes.'
        }
        [PSCustomObject]@{
            TypeId          = 'IdentityBreadcrumbTokenDecoy'
            Family          = 'IdentityTokenBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 10
            TelemetryProfile = 'Windows-Identity-Token'
            Description     = 'Deploys fake identity breadcrumbs and privileged account references with embedded canary token strings.'
        }
        [PSCustomObject]@{
            TypeId          = 'CloudApiCanaryTokenDecoy'
            Family          = 'CloudTokenBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 10
            TelemetryProfile = 'Windows-Identity-Token'
            Description     = 'Deploys fake OAuth/API token material and cloud endpoint references for high-confidence misuse detection.'
        }
        [PSCustomObject]@{
            TypeId          = 'CredentialFileTokenDecoy'
            Family          = 'CredentialBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 9
            TelemetryProfile = 'Windows-Identity-Token'
            Description     = 'Deploys fake credential note files and runbook snippets with canary usernames/password tokens.'
        }
        [PSCustomObject]@{
            TypeId          = 'ServiceCredentialPackDecoy'
            Family          = 'ServiceCredentialBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 10
            TelemetryProfile = 'Windows-Identity-Token'
            Description     = 'Deploys vault-like fake service credential packs with embedded canary tokens and owner hints.'
        }
        [PSCustomObject]@{
            TypeId          = 'CanaryTextTokenPackDecoy'
            Family          = 'TokenTextBait'
            Platforms       = @('Windows')
            Capabilities    = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')
            RiskLevel       = 'Low'
            CostScore       = 1
            DetectionScore  = 10
            TelemetryProfile = 'Windows-Identity-Token'
            Description     = 'Deploys low-cost script/config/docs canary text-token packs for high-confidence file-access detection.'
        }
    )

    return [PSCustomObject]@{
        Version  = '1.0'
        Platform = 'Windows'
        Types    = $types
    }
}

function Get-PrivateF4keH0undElementTypeRegistry {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    $registrySettings = Get-F4keH0undConfig -Section 'ElementRegistrySettings'
    $registryPath = Get-PrivateF4keH0undElementRegistryPath

    if ($registrySettings.EnableExternalRegistry -eq $false) {
        return Get-PrivateF4keH0undDefaultElementTypeRegistry
    }

    if (-not (Test-Path -Path $registryPath -PathType Leaf)) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Element registry not found at '$registryPath'. Falling back to defaults."
        return Get-PrivateF4keH0undDefaultElementTypeRegistry
    }

    try {
        $registryRaw = Get-Content -Path $registryPath -Raw -ErrorAction Stop
        $registry = $registryRaw | ConvertFrom-Json -ErrorAction Stop

        if (-not $registry.Types) {
            throw "Element registry does not contain a 'Types' array."
        }

        return $registry
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed loading element registry at '$registryPath'. Falling back to defaults. Error: $($_.Exception.Message)"
        return Get-PrivateF4keH0undDefaultElementTypeRegistry
    }
}

function Get-PrivateF4keH0undElementTypeDefinition {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ElementType
    )

    $registry = Get-PrivateF4keH0undElementTypeRegistry
    $matchedTypes = @($registry.Types | Where-Object { [string]$_.TypeId -eq $ElementType })

    if (-not $matchedTypes -or $matchedTypes.Count -eq 0) {
        return $null
    }

    return $matchedTypes | Select-Object -First 1
}

function New-PrivateF4keH0undElementId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ElementType
    )

    $shortType = ($ElementType -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
    $guid = [guid]::NewGuid().ToString('N').Substring(0, 12)
    return "fhlg-win-$shortType-$guid"
}
