function Get-PrivateF4keH0undWindowsDeploymentDefaults {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    $settings = Get-F4keH0undConfig -Section 'WindowsDeploymentSettings'
    if ($null -eq $settings) {
        $settings = (Get-F4keH0undDefaultConfig).WindowsDeploymentSettings
    }

    [PSCustomObject]@{
        ArtifactRoot  = if ($settings.ArtifactRoot) { [string]$settings.ArtifactRoot } else { 'C:\ProgramData\F4keH0und-LG\Elements' }
        Port          = if ($settings.Port) { [int]$settings.Port } else { 5985 }
        UseSSL        = [bool]$settings.UseSSL
        Authentication = if ($settings.Authentication) { [string]$settings.Authentication } else { 'Negotiate' }
        ThrottleLimit = if ($settings.ThrottleLimit) { [int]$settings.ThrottleLimit } else { 10 }
    }
}

function Convert-PrivateF4keH0undTemplateDataToHashtable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [System.Collections.IDictionary]$TemplateData
    )

    $result = @{}
    if ($null -eq $TemplateData) {
        return $result
    }

    foreach ($keyObject in $TemplateData.Keys) {
        $keyName = [string]$keyObject
        $result[$keyName] = $TemplateData[$keyObject]
    }

    return $result
}

function Convert-PrivateF4keH0undObjectToHashtable {
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

function Convert-PrivateF4keH0undValueToSafeFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $safeValue = $Value -replace '[^a-zA-Z0-9._-]', '-'
    if ([string]::IsNullOrWhiteSpace($safeValue)) {
        return 'element'
    }

    return $safeValue
}

function New-PrivateF4keH0undElementArtifactSpec {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ElementType,

        [Parameter(Mandatory = $true)]
        [string]$ElementName,

        [Parameter(Mandatory = $true)]
        [hashtable]$TemplateData
    )

    $safeName = Convert-PrivateF4keH0undValueToSafeFileName -Value $ElementName
    $generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $templateJson = ($TemplateData | ConvertTo-Json -Depth 8)

    switch ($ElementType) {
        'ServiceDefinitionDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "services/$safeName.service.decoy.json"
                    Content      = (@{
                            Name            = $ElementName
                            DisplayName     = if ($TemplateData['DisplayName']) { [string]$TemplateData['DisplayName'] } else { "Legacy Service $ElementName" }
                            BinaryPath      = if ($TemplateData['BinaryPath']) { [string]$TemplateData['BinaryPath'] } else { 'C:\Program Files\LegacySvc\legacysvc.exe' }
                            StartupType     = if ($TemplateData['StartupType']) { [string]$TemplateData['StartupType'] } else { 'Automatic' }
                            ServiceAccount  = if ($TemplateData['ServiceAccount']) { [string]$TemplateData['ServiceAccount'] } else { 'corp\\svc_legacy' }
                            Description     = if ($TemplateData['Description']) { [string]$TemplateData['Description'] } else { 'Legacy middleware service retained for compatibility.' }
                            GeneratedAtUtc  = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
                [PSCustomObject]@{
                    RelativePath = "runbooks/$safeName-service-credentials.txt"
                    Content      = @"
[$ElementName] Legacy Service Recovery Notes

- Account: $(if ($TemplateData['ServiceAccount']) { [string]$TemplateData['ServiceAccount'] } else { 'corp\\svc_legacy' })
- Config: C:\ProgramData\Legacy\$safeName\service.config
- Escalation Group: Middleware-Ops

GeneratedAtUtc: $generatedUtc
TemplateData:
$templateJson
"@
                }
            )
        }

        'RpcEndpointDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "rpc/$safeName-endpoints.json"
                    Content      = (@{
                            Name           = $ElementName
                            PipeName       = if ($TemplateData['PipeName']) { [string]$TemplateData['PipeName'] } else { "\\\\.\\pipe\\$safeName-rpc" }
                            Endpoint       = if ($TemplateData['Endpoint']) { [string]$TemplateData['Endpoint'] } else { 'ncacn_np' }
                            Version        = if ($TemplateData['Version']) { [string]$TemplateData['Version'] } else { '2.3' }
                            AuthProfile    = if ($TemplateData['AuthProfile']) { [string]$TemplateData['AuthProfile'] } else { 'LegacyIntegrated' }
                            GeneratedAtUtc = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
                [PSCustomObject]@{
                    RelativePath = "rpc/$safeName-client-profile.ini"
                    Content      = @"
[RpcClient]
Name=$ElementName
Pipe=$(if ($TemplateData['PipeName']) { [string]$TemplateData['PipeName'] } else { "\\\\.\\pipe\\$safeName-rpc" })
Protocol=$(if ($TemplateData['Endpoint']) { [string]$TemplateData['Endpoint'] } else { 'ncacn_np' })
Auth=$(if ($TemplateData['AuthProfile']) { [string]$TemplateData['AuthProfile'] } else { 'LegacyIntegrated' })

GeneratedAtUtc=$generatedUtc
"@
                }
            )
        }

        'ApiHookConfigDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "api/$safeName-appsettings.decoy.json"
                    Content      = (@{
                            Name            = $ElementName
                            ApiBaseUrl      = if ($TemplateData['ApiBaseUrl']) { [string]$TemplateData['ApiBaseUrl'] } else { 'https://legacy-api.internal.corp' }
                            WebhookUrl      = if ($TemplateData['WebhookUrl']) { [string]$TemplateData['WebhookUrl'] } else { 'https://hooks.internal.corp/legacy' }
                            ApiToken        = if ($TemplateData['ApiToken']) { [string]$TemplateData['ApiToken'] } else { "fhlg-token-$([guid]::NewGuid().ToString('N').Substring(0,20))" }
                            IntegrationName = if ($TemplateData['IntegrationName']) { [string]$TemplateData['IntegrationName'] } else { 'LegacyBillingSync' }
                            GeneratedAtUtc  = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
                [PSCustomObject]@{
                    RelativePath = "api/$safeName.env.decoy"
                    Content      = @"
INTEGRATION_NAME=$(if ($TemplateData['IntegrationName']) { [string]$TemplateData['IntegrationName'] } else { 'LegacyBillingSync' })
API_BASE_URL=$(if ($TemplateData['ApiBaseUrl']) { [string]$TemplateData['ApiBaseUrl'] } else { 'https://legacy-api.internal.corp' })
WEBHOOK_URL=$(if ($TemplateData['WebhookUrl']) { [string]$TemplateData['WebhookUrl'] } else { 'https://hooks.internal.corp/legacy' })
API_TOKEN=$(if ($TemplateData['ApiToken']) { [string]$TemplateData['ApiToken'] } else { "fhlg-token-$([guid]::NewGuid().ToString('N').Substring(0,20))" })
GENERATED_UTC=$generatedUtc
"@
                }
            )
        }

        'ProcessThreadArtifactDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "runtime/$safeName-thread-map.txt"
                    Content      = @"
[$ElementName] Runtime Thread Map (Legacy Snapshot)

PrimaryProcess: $(if ($TemplateData['PrimaryProcess']) { [string]$TemplateData['PrimaryProcess'] } else { 'legacysync.exe' })
CriticalThread: $(if ($TemplateData['CriticalThread']) { [string]$TemplateData['CriticalThread'] } else { 'WorkerThread-AuthRefresh' })
FallbackThread: $(if ($TemplateData['FallbackThread']) { [string]$TemplateData['FallbackThread'] } else { 'WorkerThread-ReplayQueue' })

GeneratedAtUtc: $generatedUtc
"@
                }
                [PSCustomObject]@{
                    RelativePath = "runtime/$safeName-process-notes.ps1"
                    Content      = @"
# $ElementName - Legacy Runtime Notes
# GeneratedAtUtc: $generatedUtc
`$LegacyProcess = "$(if ($TemplateData['PrimaryProcess']) { [string]$TemplateData['PrimaryProcess'] } else { 'legacysync.exe' })"
`$CriticalThread = "$(if ($TemplateData['CriticalThread']) { [string]$TemplateData['CriticalThread'] } else { 'WorkerThread-AuthRefresh' })"
Write-Output "Attach debugger to `$LegacyProcess and inspect `$CriticalThread"
"@
                }
            )
        }

        'IdentityBreadcrumbTokenDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "identity/$safeName-identity-map.decoy.txt"
                    Content      = @"
[$ElementName] Legacy Identity Mapping Notes

PrivilegedSamAccountName: $(if ($TemplateData['PrivilegedSamAccountName']) { [string]$TemplateData['PrivilegedSamAccountName'] } else { 'svc_legacy_sync' })
EntraUserPrincipalName: $(if ($TemplateData['EntraUserPrincipalName']) { [string]$TemplateData['EntraUserPrincipalName'] } else { 'svc-legacy-sync@contoso.onmicrosoft.com' })
OnCallAlias: $(if ($TemplateData['OnCallAlias']) { [string]$TemplateData['OnCallAlias'] } else { 'middleware-tier3' })
RoleTitle: $(if ($TemplateData['RoleTitle']) { [string]$TemplateData['RoleTitle'] } else { 'Identity Platform Engineer' })
Department: $(if ($TemplateData['Department']) { [string]$TemplateData['Department'] } else { 'Legacy Integration' })
GroupHint: $(if ($TemplateData['GroupHint']) { [string]$TemplateData['GroupHint'] } else { 'Tier3-Identity-Operations' })
IdentityOwnerHint: $(if ($TemplateData['IdentityOwnerHint']) { [string]$TemplateData['IdentityOwnerHint'] } else { 'svc-owner@contoso.com' })
IdentityCanaryToken: $(if ($TemplateData['CanaryToken']) { [string]$TemplateData['CanaryToken'] } else { "fhlg-idtoken-$([guid]::NewGuid().ToString('N').Substring(0,18))" })

GeneratedAtUtc: $generatedUtc
"@
                }
                [PSCustomObject]@{
                    RelativePath = "identity/$safeName-entra-link.decoy.json"
                    Content      = (@{
                            Name                    = $ElementName
                            PrivilegedSamAccountName = if ($TemplateData['PrivilegedSamAccountName']) { [string]$TemplateData['PrivilegedSamAccountName'] } else { 'svc_legacy_sync' }
                            EntraUserPrincipalName  = if ($TemplateData['EntraUserPrincipalName']) { [string]$TemplateData['EntraUserPrincipalName'] } else { 'svc-legacy-sync@contoso.onmicrosoft.com' }
                            ImmutableIdHint         = if ($TemplateData['ImmutableIdHint']) { [string]$TemplateData['ImmutableIdHint'] } else { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((if ($TemplateData['PrivilegedSamAccountName']) { [string]$TemplateData['PrivilegedSamAccountName'] } else { 'svc_legacy_sync' }))) }
                            RoleTitle               = if ($TemplateData['RoleTitle']) { [string]$TemplateData['RoleTitle'] } else { 'Identity Platform Engineer' }
                            Department              = if ($TemplateData['Department']) { [string]$TemplateData['Department'] } else { 'Legacy Integration' }
                            GroupHint               = if ($TemplateData['GroupHint']) { [string]$TemplateData['GroupHint'] } else { 'Tier3-Identity-Operations' }
                            IdentityOwnerHint       = if ($TemplateData['IdentityOwnerHint']) { [string]$TemplateData['IdentityOwnerHint'] } else { 'svc-owner@contoso.com' }
                            CanaryToken             = if ($TemplateData['CanaryToken']) { [string]$TemplateData['CanaryToken'] } else { "fhlg-idtoken-$([guid]::NewGuid().ToString('N').Substring(0,18))" }
                            GeneratedAtUtc          = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
            )
        }

        'CloudApiCanaryTokenDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "tokens/$safeName-oauth-cache.decoy.json"
                    Content      = (@{
                            Name            = $ElementName
                            TenantId        = if ($TemplateData['TenantId']) { [string]$TemplateData['TenantId'] } else { '11111111-2222-3333-4444-555555555555' }
                            ClientId        = if ($TemplateData['ClientId']) { [string]$TemplateData['ClientId'] } else { 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
                            Scope           = if ($TemplateData['Scope']) { [string]$TemplateData['Scope'] } else { 'https://graph.microsoft.com/.default' }
                            RefreshToken    = if ($TemplateData['RefreshToken']) { [string]$TemplateData['RefreshToken'] } else { "fhlg-refresh-$([guid]::NewGuid().ToString('N'))" }
                            AccessTokenHint = if ($TemplateData['AccessTokenHint']) { [string]$TemplateData['AccessTokenHint'] } else { "eyJhbGciOiJIUzI1NiIsImtpZCI6ImZo...$([guid]::NewGuid().ToString('N').Substring(0,12))" }
                            GeneratedAtUtc  = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
                [PSCustomObject]@{
                    RelativePath = "tokens/$safeName-cloud.env.decoy"
                    Content      = @"
AZURE_TENANT_ID=$(if ($TemplateData['TenantId']) { [string]$TemplateData['TenantId'] } else { '11111111-2222-3333-4444-555555555555' })
AZURE_CLIENT_ID=$(if ($TemplateData['ClientId']) { [string]$TemplateData['ClientId'] } else { 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' })
AZURE_SCOPE=$(if ($TemplateData['Scope']) { [string]$TemplateData['Scope'] } else { 'https://graph.microsoft.com/.default' })
AZURE_REFRESH_TOKEN=$(if ($TemplateData['RefreshToken']) { [string]$TemplateData['RefreshToken'] } else { "fhlg-refresh-$([guid]::NewGuid().ToString('N'))" })
CANARY_TOKEN=$(if ($TemplateData['CanaryToken']) { [string]$TemplateData['CanaryToken'] } else { "fhlg-cloudtoken-$([guid]::NewGuid().ToString('N').Substring(0,20))" })
GENERATED_UTC=$generatedUtc
"@
                }
            )
        }

        'CredentialFileTokenDecoy' {
            return @(
                [PSCustomObject]@{
                    RelativePath = "creds/$safeName-legacy-credentials.decoy.txt"
                    Content      = @"
[$ElementName] Legacy Service Credential Notes

ServiceAccount: $(if ($TemplateData['ServiceAccount']) { [string]$TemplateData['ServiceAccount'] } else { 'corp\\svc_legacy_backup' })
PasswordHint: $(if ($TemplateData['PasswordHint']) { [string]$TemplateData['PasswordHint'] } else { 'Winter2023!_RotateAfterCutover' })
VaultPath: $(if ($TemplateData['VaultPath']) { [string]$TemplateData['VaultPath'] } else { 'C:\\Ops\\VaultExports\\legacy-sync.txt' })
CanaryToken: $(if ($TemplateData['CanaryToken']) { [string]$TemplateData['CanaryToken'] } else { "fhlg-credtoken-$([guid]::NewGuid().ToString('N').Substring(0,20))" })

GeneratedAtUtc: $generatedUtc
"@
                }
                [PSCustomObject]@{
                    RelativePath = "creds/$safeName-vault-export.decoy.csv"
                    Content      = @"
System,Username,Secret,CanaryToken,UpdatedUtc
LegacySQL,$(if ($TemplateData['ServiceAccount']) { [string]$TemplateData['ServiceAccount'] } else { 'corp\\svc_legacy_backup' }),$(if ($TemplateData['PasswordHint']) { [string]$TemplateData['PasswordHint'] } else { 'Winter2023!_RotateAfterCutover' }),$(if ($TemplateData['CanaryToken']) { [string]$TemplateData['CanaryToken'] } else { "fhlg-credtoken-$([guid]::NewGuid().ToString('N').Substring(0,20))" }),$generatedUtc
"@
                }
            )
        }

        'CanaryTextTokenPackDecoy' {
            $baseCanaryToken = if ($TemplateData['CanaryToken']) {
                [string]$TemplateData['CanaryToken']
            }
            else {
                "fhlg-texttoken-$([guid]::NewGuid().ToString('N').Substring(0,20))"
            }

            $scriptCanaryToken = if ($TemplateData['ScriptCanaryToken']) {
                [string]$TemplateData['ScriptCanaryToken']
            }
            else {
                "$baseCanaryToken-script"
            }

            $configCanaryToken = if ($TemplateData['ConfigCanaryToken']) {
                [string]$TemplateData['ConfigCanaryToken']
            }
            else {
                "$baseCanaryToken-config"
            }

            $docsCanaryToken = if ($TemplateData['DocsCanaryToken']) {
                [string]$TemplateData['DocsCanaryToken']
            }
            else {
                "$baseCanaryToken-docs"
            }

            return @(
                [PSCustomObject]@{
                    RelativePath = "scripts/$safeName-maintenance.decoy.ps1"
                    Content      = @"
# $ElementName - Legacy Maintenance Helper
# GeneratedAtUtc: $generatedUtc

`$RepositoryHint = "$(if ($TemplateData['RepositoryHint']) { [string]$TemplateData['RepositoryHint'] } else { 'legacy-identity-automation' })"
`$IdentityOwnerHint = "$(if ($TemplateData['IdentityOwnerHint']) { [string]$TemplateData['IdentityOwnerHint'] } else { 'identity.ops@contoso.com' })"
`$GroupHint = "$(if ($TemplateData['GroupHint']) { [string]$TemplateData['GroupHint'] } else { 'Identity-Engineering' })"
`$CanaryToken = "$scriptCanaryToken"

Write-Output "Repository=`$RepositoryHint Owner=`$IdentityOwnerHint Group=`$GroupHint Token=`$CanaryToken"
"@
                }
                [PSCustomObject]@{
                    RelativePath = "config/$safeName-legacy.settings.decoy.json"
                    Content      = (@{
                            Name               = $ElementName
                            RepositoryHint     = if ($TemplateData['RepositoryHint']) { [string]$TemplateData['RepositoryHint'] } else { 'legacy-identity-automation' }
                            IdentityOwnerHint  = if ($TemplateData['IdentityOwnerHint']) { [string]$TemplateData['IdentityOwnerHint'] } else { 'identity.ops@contoso.com' }
                            GroupHint          = if ($TemplateData['GroupHint']) { [string]$TemplateData['GroupHint'] } else { 'Identity-Engineering' }
                            CanaryTextToken    = $configCanaryToken
                            GeneratedAtUtc     = $generatedUtc
                        } | ConvertTo-Json -Depth 6)
                }
                [PSCustomObject]@{
                    RelativePath = "docs/$safeName-operator-runbook.decoy.md"
                    Content      = @"
# $ElementName - Legacy Operator Notes

- Repository: $(if ($TemplateData['RepositoryHint']) { [string]$TemplateData['RepositoryHint'] } else { 'legacy-identity-automation' })
- Owner: $(if ($TemplateData['IdentityOwnerHint']) { [string]$TemplateData['IdentityOwnerHint'] } else { 'identity.ops@contoso.com' })
- Group: $(if ($TemplateData['GroupHint']) { [string]$TemplateData['GroupHint'] } else { 'Identity-Engineering' })
- CanaryToken: $docsCanaryToken

GeneratedAtUtc: $generatedUtc
"@
                }
            )
        }

        default {
            throw "Unsupported ElementType '$ElementType'."
        }
    }
}

function New-PrivateF4keH0undWinRMSession {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [bool]$UseSSL,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')]
        [string]$Authentication
    )

    $sessionParams = @{
        ComputerName   = $ComputerName
        Port           = $Port
        ErrorAction    = 'Stop'
        Authentication = $Authentication
    }

    if ($UseSSL) {
        $sessionParams['UseSSL'] = $true
    }

    if ($PSBoundParameters.ContainsKey('Credential')) {
        $sessionParams['Credential'] = $Credential
    }

    return New-PSSession @sessionParams
}

function Invoke-PrivateF4keH0undWindowsElementRemoteOperation {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Deploy', 'Update', 'Disable', 'Enable', 'Remove')]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Payload,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [int]$Port,

        [Parameter()]
        [bool]$UseSSL,

        [Parameter()]
        [ValidateSet('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')]
        [string]$Authentication
    )

    $session = $null
    try {
        $sessionParams = @{
            ComputerName   = $ComputerName
            Port           = $Port
            UseSSL         = $UseSSL
            Authentication = $Authentication
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $sessionParams['Credential'] = $Credential
        }

        $session = New-PrivateF4keH0undWinRMSession @sessionParams

        $scriptBlock = {
            param(
                [string]$Operation,
                [hashtable]$Payload
            )

            $basePath = [string]$Payload.BasePath
            if ([string]::IsNullOrWhiteSpace($basePath)) {
                throw 'BasePath is required in payload.'
            }

            $statePath = Join-Path -Path $basePath -ChildPath 'state.json'

            $ensureDirectory = {
                param([string]$Path)

                if (-not (Test-Path -Path $Path -PathType Container)) {
                    New-Item -Path $Path -ItemType Directory -Force | Out-Null
                }
            }

            $loadState = {
                if (Test-Path -Path $statePath -PathType Leaf) {
                    return Get-Content -Path $statePath -Raw | ConvertFrom-Json
                }
                return $null
            }

            $saveState = {
                param([hashtable]$State)
                $jsonState = $State | ConvertTo-Json -Depth 10
                Set-Content -Path $statePath -Value $jsonState -Encoding UTF8 -Force
            }

            switch ($Operation) {
                'Deploy' {
                    & $ensureDirectory -Path $basePath

                    $locations = [System.Collections.Generic.List[string]]::new()
                    foreach ($artifact in @($Payload.Artifacts)) {
                        $relativePath = [string]$artifact.RelativePath
                        $artifactPath = Join-Path -Path $basePath -ChildPath $relativePath
                        $artifactDirectory = Split-Path -Path $artifactPath -Parent
                        & $ensureDirectory -Path $artifactDirectory
                        Set-Content -Path $artifactPath -Value ([string]$artifact.Content) -Encoding UTF8 -Force
                        $locations.Add($artifactPath)
                    }

                    $utcNow = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    $stateData = [ordered]@{
                        ElementId       = [string]$Payload.ElementId
                        ElementType     = [string]$Payload.ElementType
                        ElementName     = [string]$Payload.ElementName
                        ElementFamily   = [string]$Payload.ElementFamily
                        ComputerName    = $env:COMPUTERNAME
                        Enabled         = $true
                        Status          = 'Armed'
                        CreatedAtUtc    = $utcNow
                        UpdatedAtUtc    = $utcNow
                        Tags            = @($Payload.Tags)
                        TemplateData    = $Payload.TemplateData
                        TelemetryProfile = [string]$Payload.TelemetryProfile
                        Locations       = @($locations)
                    }

                    & $saveState -State $stateData

                    return [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        BasePath     = $basePath
                        StatePath    = $statePath
                        Locations    = @($locations)
                        Status       = 'Armed'
                    }
                }

                'Update' {
                    if (-not (Test-Path -Path $basePath -PathType Container)) {
                        throw "Element base path '$basePath' was not found."
                    }

                    $existingState = & $loadState
                    if ($null -eq $existingState) {
                        throw "Element state file '$statePath' was not found."
                    }

                    $locations = [System.Collections.Generic.List[string]]::new()
                    foreach ($artifact in @($Payload.Artifacts)) {
                        $artifactPath = Join-Path -Path $basePath -ChildPath ([string]$artifact.RelativePath)
                        $artifactDirectory = Split-Path -Path $artifactPath -Parent
                        & $ensureDirectory -Path $artifactDirectory
                        Set-Content -Path $artifactPath -Value ([string]$artifact.Content) -Encoding UTF8 -Force
                        $locations.Add($artifactPath)
                    }

                    $status = if ($existingState.Enabled) { 'Armed' } else { 'Disabled' }
                    $updatedState = [ordered]@{
                        ElementId       = [string]$Payload.ElementId
                        ElementType     = [string]$Payload.ElementType
                        ElementName     = [string]$Payload.ElementName
                        ElementFamily   = [string]$Payload.ElementFamily
                        ComputerName    = $env:COMPUTERNAME
                        Enabled         = [bool]$existingState.Enabled
                        Status          = $status
                        CreatedAtUtc    = if ($existingState.CreatedAtUtc) { [string]$existingState.CreatedAtUtc } else { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                        UpdatedAtUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        Tags            = @($Payload.Tags)
                        TemplateData    = $Payload.TemplateData
                        TelemetryProfile = [string]$Payload.TelemetryProfile
                        Locations       = @($locations)
                    }

                    & $saveState -State $updatedState

                    return [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        BasePath     = $basePath
                        StatePath    = $statePath
                        Locations    = @($locations)
                        Status       = $status
                    }
                }

                'Disable' {
                    $stateData = & $loadState
                    if ($null -eq $stateData) {
                        throw "Element state file '$statePath' was not found."
                    }

                    $stateData.Enabled = $false
                    $stateData.Status = 'Disabled'
                    $stateData.UpdatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    if ($Payload.ContainsKey('Reason') -and -not [string]::IsNullOrWhiteSpace([string]$Payload.Reason)) {
                        $stateData.DisabledReason = [string]$Payload.Reason
                    }

                    & $saveState -State $stateData

                    return [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        BasePath     = $basePath
                        StatePath    = $statePath
                        Locations    = @($stateData.Locations)
                        Status       = 'Disabled'
                    }
                }

                'Enable' {
                    $stateData = & $loadState
                    if ($null -eq $stateData) {
                        throw "Element state file '$statePath' was not found."
                    }

                    $stateData.Enabled = $true
                    $stateData.Status = 'Armed'
                    $stateData.UpdatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

                    & $saveState -State $stateData

                    return [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        BasePath     = $basePath
                        StatePath    = $statePath
                        Locations    = @($stateData.Locations)
                        Status       = 'Armed'
                    }
                }

                'Remove' {
                    $existingState = & $loadState
                    $locations = if ($existingState -and $existingState.Locations) { @($existingState.Locations) } else { @() }

                    if (Test-Path -Path $basePath -PathType Container) {
                        Remove-Item -Path $basePath -Recurse -Force -ErrorAction Stop
                    }

                    return [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        BasePath     = $basePath
                        StatePath    = $statePath
                        Locations    = @($locations)
                        Status       = 'Removed'
                    }
                }
            }
        }

        return Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Operation, $Payload -ErrorAction Stop
    }
    finally {
        if ($null -ne $session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

function Get-PrivateF4keH0undWindowsElementState {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ElementId,

        [Parameter()]
        [switch]$IncludeRemoved
    )

    $states = @(Get-F4keH0undInventoryState -IncludeRemoved:$IncludeRemoved)
    $matchedStates = @(
        $states | Where-Object {
            [string]$_.Platform -eq 'Windows' -and
            [string]$_.Identity -eq $ElementId
        }
    )

    if (-not $matchedStates -or $matchedStates.Count -eq 0) {
        return $null
    }

    return $matchedStates | Sort-Object -Property @{ Expression = 'LastUpdated'; Descending = $true } | Select-Object -First 1
}

function Invoke-PrivateF4keH0undWindowsElementLifecycle {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Deploy', 'Update', 'Disable', 'Enable', 'Remove')]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$ElementId,

        [Parameter(Mandatory = $true)]
        [string]$ElementType,

        [Parameter(Mandatory = $true)]
        [string]$ElementName,

        [Parameter(Mandatory = $true)]
        [string]$ElementFamily,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactRoot,

        [Parameter()]
        [hashtable]$TemplateData = @{},

        [Parameter()]
        [string[]]$Tags = @(),

        [Parameter()]
        [string]$Reason,

        [Parameter()]
        [string]$TelemetryProfile,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [int]$Port,

        [Parameter()]
        [bool]$UseSSL,

        [Parameter()]
        [ValidateSet('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')]
        [string]$Authentication
    )

    $safeElementId = Convert-PrivateF4keH0undValueToSafeFileName -Value $ElementId
    $basePath = Join-Path -Path $ArtifactRoot -ChildPath $safeElementId

    $payload = @{
        ElementId        = $ElementId
        ElementType      = $ElementType
        ElementName      = $ElementName
        ElementFamily    = $ElementFamily
        BasePath         = $basePath
        TemplateData     = $TemplateData
        Tags             = @($Tags)
        TelemetryProfile = $TelemetryProfile
    }

    if ($Action -in @('Deploy', 'Update')) {
        $payload['Artifacts'] = @(New-PrivateF4keH0undElementArtifactSpec -ElementType $ElementType -ElementName $ElementName -TemplateData $TemplateData)
    }

    if ($Action -eq 'Disable' -and -not [string]::IsNullOrWhiteSpace($Reason)) {
        $payload['Reason'] = $Reason
    }

    $invokeParams = @{
        Operation      = $Action
        ComputerName   = $ComputerName
        Payload        = $payload
        Port           = $Port
        UseSSL         = $UseSSL
        Authentication = $Authentication
    }

    if ($PSBoundParameters.ContainsKey('Credential')) {
        $invokeParams['Credential'] = $Credential
    }

    $remoteResult = Invoke-PrivateF4keH0undWindowsElementRemoteOperation @invokeParams

    [PSCustomObject]@{
        ElementId        = $ElementId
        ElementType      = $ElementType
        ElementFamily    = $ElementFamily
        ElementName      = $ElementName
        ComputerName     = $ComputerName
        Platform         = 'Windows'
        BasePath         = $remoteResult.BasePath
        Locations        = @($remoteResult.Locations)
        Status           = [string]$remoteResult.Status
        TelemetryProfile = $TelemetryProfile
    }
}
