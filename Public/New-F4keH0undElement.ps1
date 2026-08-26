<#
.SYNOPSIS
    Deploys Windows artifact deception elements via WinRM/PSRP.

.DESCRIPTION
    Creates Windows-specific deceptive artifacts on target hosts using the
    element type registry and records lifecycle inventory events.

.PARAMETER ElementType
    Element type to deploy. Supported values are read from
    Get-F4keH0undElementType.

.PARAMETER ComputerName
    One or more Windows hosts targeted through WinRM/PSRP.

.PARAMETER Name
    Optional logical name for the element.

.PARAMETER TemplateData
    Optional hashtable used to render element artifacts.

.PARAMETER ArtifactRoot
    Optional override for remote artifact root path.

.PARAMETER Tag
    Optional tags saved with inventory metadata.

.PARAMETER Credential
    Optional credential for WinRM remoting.

.PARAMETER Port
    WinRM port. Defaults from config.

.PARAMETER UseSSL
    Use WinRM over HTTPS.

.PARAMETER Authentication
    WinRM authentication method.

.PARAMETER ThrottleLimit
    Reserved for parallelized deployment workflows.

.PARAMETER RolloutProfile
    Optional rollout profile (`Lab`, `Pilot`, `Production`) used to apply
    Phase 5 deployment defaults.

.PARAMETER AuditLogPath
    Optional audit log destination persisted in metadata.

.PARAMETER PassThru
    Returns deployed element records.

.EXAMPLE
    New-F4keH0undElement -ElementType ApiHookConfigDecoy -ComputerName WIN-APP-01

.EXAMPLE
    New-F4keH0undElement -ElementType ServiceDefinitionDecoy -ComputerName WIN-SRV-01,WIN-SRV-02 -Credential (Get-Credential) -WhatIf
#>
function New-F4keH0undElement {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ElementType,

        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [System.Collections.IDictionary]$TemplateData,

        [Parameter()]
        [string]$ArtifactRoot,

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
        [int]$ThrottleLimit,

        [Parameter()]
        [ValidateSet('Lab', 'Pilot', 'Production')]
        [string]$RolloutProfile,

        [Parameter()]
        [string]$AuditLogPath,

        [Parameter()]
        [switch]$PassThru
    )

    $typeDefinition = Get-PrivateF4keH0undElementTypeDefinition -ElementType $ElementType
    if ($null -eq $typeDefinition) {
        Write-Error "[ERROR] Unsupported ElementType '$ElementType'. Use Get-F4keH0undElementType to list supported values."
        return
    }

    $defaults = Get-PrivateF4keH0undWindowsDeploymentDefaults
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

    if (-not $PSBoundParameters.ContainsKey('ArtifactRoot')) { $ArtifactRoot = $defaults.ArtifactRoot }
    if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $defaults.Port }
    if (-not $PSBoundParameters.ContainsKey('Authentication')) { $Authentication = $defaults.Authentication }
    if (-not $PSBoundParameters.ContainsKey('ThrottleLimit')) { $ThrottleLimit = [int]$resolvedRolloutProfile.WindowsThrottleLimit }

    $useSslValue = if ($PSBoundParameters.ContainsKey('UseSSL')) { [bool]$UseSSL } else { [bool]$defaults.UseSSL }
    $templateTable = Convert-PrivateF4keH0undTemplateDataToHashtable -TemplateData $TemplateData

    $telemetrySettings = Get-F4keH0undConfig -Section 'TelemetrySettings'
    $telemetryProfile = if ($telemetrySettings.DefaultTelemetryProfile) {
        [string]$telemetrySettings.DefaultTelemetryProfile
    }
    elseif ($typeDefinition.TelemetryProfile) {
        [string]$typeDefinition.TelemetryProfile
    }
    else {
        'Windows-Artifact-Baseline'
    }

    $deployed = [System.Collections.Generic.List[PSObject]]::new()

    for ($index = 0; $index -lt $ComputerName.Count; $index++) {
        $targetComputer = [string]$ComputerName[$index]
        if ([string]::IsNullOrWhiteSpace($targetComputer)) {
            continue
        }

        $elementId = New-PrivateF4keH0undElementId -ElementType $ElementType
        $elementName = if ([string]::IsNullOrWhiteSpace($Name)) {
            "$ElementType-$targetComputer"
        }
        else {
            $Name
        }

        $target = "$targetComputer [$ElementType]"
        $action = "Deploy Windows deceptive element '$elementName'"
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            continue
        }

        try {
            $invokeParams = @{
                Action           = 'Deploy'
                ElementId        = $elementId
                ElementType      = $ElementType
                ElementName      = $elementName
                ElementFamily    = [string]$typeDefinition.Family
                ComputerName     = $targetComputer
                ArtifactRoot     = $ArtifactRoot
                TemplateData     = $templateTable
                Tags             = @($Tag)
                TelemetryProfile = $telemetryProfile
                Port             = $Port
                UseSSL           = $useSslValue
                Authentication   = $Authentication
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParams['Credential'] = $Credential
            }

            $result = Invoke-PrivateF4keH0undWindowsElementLifecycle @invokeParams
            $deployed.Add($result)

            $eventMetadata = @{
                ComputerName      = $targetComputer
                ElementName       = $elementName
                ElementFamily     = [string]$typeDefinition.Family
                Tags              = @($Tag)
                TemplateData      = $templateTable
                DeploymentChannel = 'WinRM/PSRP'
                TelemetryProfile  = $telemetryProfile
                ArtifactRoot      = $ArtifactRoot
                ArtifactLocations = @($result.Locations)
                ThrottleLimit     = $ThrottleLimit
                RolloutProfile    = [string]$resolvedRolloutProfile.Name
                AuditLogPath      = $AuditLogPath
            }

            if ([string]$typeDefinition.Family -match 'Identity|Token|Credential') {
                $eventMetadata['TokenPathHints'] = @($result.Locations)
            }

            if ([string]$ElementType -eq 'CanaryTextTokenPackDecoy') {
                $eventMetadata['CollectionHookPresets'] = @('CanaryTextPackSysmonFileCreate', 'CanaryTextPackSecurityObjectAccess')
            }
            elseif ([string]$ElementType -eq 'ServiceCredentialPackDecoy') {
                $eventMetadata['CollectionHookPresets'] = @('ServiceCredentialPackSysmonFileCreate', 'ServiceCredentialPackSecurityObjectAccess')
            }
            elseif ([string]$ElementType -eq 'AdminTroubleshootingTokenPackDecoy') {
                $eventMetadata['CollectionHookPresets'] = @('AdminTroubleshootingPackSysmonFileCreate', 'AdminTroubleshootingPackSecurityObjectAccess')
            }

            Write-F4keH0undInventoryEvent -Action 'Deploy' -Identity $elementId -DecoyType $ElementType -Platform 'Windows' -ObjectType 'Element' -Strategy 'Create' -Status $result.Status -Location $result.BasePath -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Warning "[WARNING] Failed deploying element '$elementName' to '$targetComputer'. Error: $($_.Exception.Message)"
        }
    }

    if ($PassThru) {
        return @($deployed)
    }

    return [PSCustomObject]@{
        RequestedCount = @($ComputerName).Count
        DeployedCount  = $deployed.Count
        ElementType    = $ElementType
        Platform       = 'Windows'
        RolloutProfile = [string]$resolvedRolloutProfile.Name
        Targets        = @($ComputerName)
    }
}
