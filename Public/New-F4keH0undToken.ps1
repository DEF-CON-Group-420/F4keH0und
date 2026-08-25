<#
.SYNOPSIS
    Deploys identity/token-focused Windows deception artifacts.

.DESCRIPTION
    Wrapper command that prioritizes low-cost, high-efficiency token and identity
    bait by mapping token profiles to Windows artifact element types and deploying
    them through `New-F4keH0undElement` over WinRM/PSRP.

.PARAMETER TokenType
    Token profile to deploy. Supported values:
    - IdentityBreadcrumb : fake privileged identity breadcrumbs and canary IDs
    - CloudApiCanary     : fake OAuth/API token material and cloud env hints
    - CredentialFile     : fake credential notes and vault-export bait
    - CanaryTextPack     : low-cost script/config/docs text-token canary pack

.PARAMETER ComputerName
    One or more Windows hosts targeted over WinRM/PSRP.

.PARAMETER Name
    Optional logical token package name used for artifact rendering.

.PARAMETER TemplateData
    Optional template dictionary for token payload fields.

.PARAMETER Tag
    Optional custom tags merged with default token tags.

.PARAMETER Credential
    Optional credential for WinRM remoting.

.PARAMETER Port
    WinRM port override.

.PARAMETER UseSSL
    Use WinRM over HTTPS.

.PARAMETER Authentication
    WinRM authentication method.

.PARAMETER RolloutProfile
    Optional rollout profile (`Lab`, `Pilot`, `Production`) forwarded to
    `New-F4keH0undElement`.

.PARAMETER PassThru
    Returns deployed element records from `New-F4keH0undElement`.

.EXAMPLE
    New-F4keH0undToken -TokenType IdentityBreadcrumb -ComputerName WIN-APP-01 -WhatIf

.EXAMPLE
    New-F4keH0undToken -TokenType CloudApiCanary -ComputerName WIN-API-01,WIN-API-02 -Credential (Get-Credential) -PassThru

.EXAMPLE
    New-F4keH0undToken -TokenType CanaryTextPack -ComputerName WIN-DEV-01 -Name "IdentityRepo-CanaryPack" -PassThru
#>
function New-F4keH0undToken {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter()]
        [ValidateSet('IdentityBreadcrumb', 'CloudApiCanary', 'CredentialFile', 'CanaryTextPack')]
        [string]$TokenType = 'IdentityBreadcrumb',

        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [System.Collections.IDictionary]$TemplateData,

        [Parameter()]
        [string[]]$Tag,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [int]$Port,

        [Parameter()]
        [switch]$UseSSL,

        [Parameter()]
        [ValidateSet('Default', 'Negotiate', 'Kerberos', 'CredSSP', 'Basic')]
        [string]$Authentication,

        [Parameter()]
        [ValidateSet('Lab', 'Pilot', 'Production')]
        [string]$RolloutProfile,

        [Parameter()]
        [switch]$PassThru
    )

    $resolvedRolloutProfile = if ($PSBoundParameters.ContainsKey('RolloutProfile')) {
        Get-PrivateF4keH0undRolloutProfile -Name $RolloutProfile
    }
    else {
        Get-PrivateF4keH0undRolloutProfile
    }

    if ($resolvedRolloutProfile.DefaultWhatIf -and -not $PSBoundParameters.ContainsKey('WhatIf')) {
        $WhatIfPreference = $true
        Write-Verbose "[$($MyInvocation.MyCommand)] - Rollout profile '$($resolvedRolloutProfile.Name)' enables WhatIf-by-default."
    }

    $tokenTypeMap = @{
        IdentityBreadcrumb = 'IdentityBreadcrumbTokenDecoy'
        CloudApiCanary     = 'CloudApiCanaryTokenDecoy'
        CredentialFile     = 'CredentialFileTokenDecoy'
        CanaryTextPack     = 'CanaryTextTokenPackDecoy'
    }

    $elementType = [string]$tokenTypeMap[$TokenType]
    if ([string]::IsNullOrWhiteSpace($elementType)) {
        Write-Error "[ERROR] Unsupported TokenType '$TokenType'."
        return
    }

    $templateTable = Convert-PrivateF4keH0undTemplateDataToHashtable -TemplateData $TemplateData
    if (-not $templateTable.ContainsKey('CanaryToken')) {
        $templateTable['CanaryToken'] = "fhlg-$($TokenType.ToLowerInvariant())-$([guid]::NewGuid().ToString('N').Substring(0,18))"
    }

    if ($TokenType -eq 'CanaryTextPack') {
        if (-not $templateTable.ContainsKey('RepositoryHint')) {
            $templateTable['RepositoryHint'] = 'legacy-identity-automation'
        }
        if (-not $templateTable.ContainsKey('IdentityOwnerHint')) {
            $templateTable['IdentityOwnerHint'] = 'identity.ops@contoso.com'
        }
        if (-not $templateTable.ContainsKey('GroupHint')) {
            $templateTable['GroupHint'] = 'Identity-Engineering'
        }
    }

    $resolvedTags = [System.Collections.Generic.List[string]]::new()
    $defaultTokenTags = @('token', 'identity', "profile:$TokenType")
    if ($TokenType -eq 'CanaryTextPack') {
        $defaultTokenTags += @('phase5', 'text-token-pack')
    }
    else {
        $defaultTokenTags += @('phase4')
    }

    foreach ($defaultTag in $defaultTokenTags) {
        if (-not [string]::IsNullOrWhiteSpace($defaultTag) -and -not $resolvedTags.Contains($defaultTag)) {
            $resolvedTags.Add($defaultTag)
        }
    }
    foreach ($customTag in @($Tag)) {
        $tagValue = [string]$customTag
        if (-not [string]::IsNullOrWhiteSpace($tagValue) -and -not $resolvedTags.Contains($tagValue)) {
            $resolvedTags.Add($tagValue)
        }
    }

    $invokeParams = @{
        ElementType  = $elementType
        ComputerName = @($ComputerName)
        TemplateData = $templateTable
        Tag          = @($resolvedTags)
    }

    if ($PSBoundParameters.ContainsKey('Name')) { $invokeParams['Name'] = $Name }
    if ($PSBoundParameters.ContainsKey('Credential')) { $invokeParams['Credential'] = $Credential }
    if ($PSBoundParameters.ContainsKey('Port')) { $invokeParams['Port'] = $Port }
    if ($PSBoundParameters.ContainsKey('UseSSL')) { $invokeParams['UseSSL'] = $UseSSL }
    if ($PSBoundParameters.ContainsKey('Authentication')) { $invokeParams['Authentication'] = $Authentication }
    if ($PSBoundParameters.ContainsKey('RolloutProfile')) { $invokeParams['RolloutProfile'] = $RolloutProfile }
    if ($PassThru) { $invokeParams['PassThru'] = $true }

    $targetSummary = (@($ComputerName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ', ')
    if ($PSCmdlet.ShouldProcess($targetSummary, "Deploy token profile '$TokenType' as '$elementType'")) {
        return New-F4keH0undElement @invokeParams
    }

    return [PSCustomObject]@{
        RequestedCount = @($ComputerName).Count
        DeployedCount  = 0
        TokenType      = $TokenType
        ElementType    = $elementType
        Platform       = 'Windows'
        RolloutProfile = [string]$resolvedRolloutProfile.Name
        Targets        = @($ComputerName)
    }
}
