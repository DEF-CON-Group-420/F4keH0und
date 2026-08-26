<#
.SYNOPSIS
    Updates deployed Windows artifact deception elements.

.DESCRIPTION
    Re-renders Windows artifact decoys by ElementId and records lifecycle
    inventory update events.

.PARAMETER ElementId
    One or more deployed element identifiers.

.PARAMETER TemplateData
    Optional template overrides merged with previously saved template data.

.PARAMETER Name
    Optional replacement element name.

.PARAMETER Tag
    Optional replacement tags.

.PARAMETER ComputerName
    Optional host override. If omitted, target host is resolved from inventory metadata.

.PARAMETER Credential
    Optional credential for WinRM remoting.

.PARAMETER Port
    WinRM port override.

.PARAMETER UseSSL
    Use WinRM over HTTPS.

.PARAMETER Authentication
    WinRM authentication method.

.PARAMETER ThrottleLimit
    Reserved for parallelized lifecycle workflows.

.PARAMETER PassThru
    Returns updated element records.

.EXAMPLE
    Update-F4keH0undElement -ElementId fhlg-win-apihookconfigdecoy-a1b2c3d4e5f6 -TemplateData @{ ApiBaseUrl = 'https://legacy-api2.internal.corp' }
#>
function Update-F4keH0undElement {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$ElementId,

        [Parameter()]
        [System.Collections.IDictionary]$TemplateData,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string[]]$Tag,

        [Parameter()]
        [string[]]$ComputerName,

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
        [switch]$PassThru
    )

    begin {
        $defaults = Get-PrivateF4keH0undWindowsDeploymentDefaults
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $defaults.Port }
        if (-not $PSBoundParameters.ContainsKey('Authentication')) { $Authentication = $defaults.Authentication }
        if (-not $PSBoundParameters.ContainsKey('ThrottleLimit')) { $ThrottleLimit = $defaults.ThrottleLimit }
        $useSslValue = if ($PSBoundParameters.ContainsKey('UseSSL')) { [bool]$UseSSL } else { [bool]$defaults.UseSSL }
        $deployedRecords = [System.Collections.Generic.List[PSObject]]::new()
        $inputTemplateData = Convert-PrivateF4keH0undTemplateDataToHashtable -TemplateData $TemplateData
        $processedCount = 0
    }

    process {
        foreach ($currentElementId in @($ElementId)) {
            if ([string]::IsNullOrWhiteSpace($currentElementId)) {
                continue
            }

            $currentState = Get-PrivateF4keH0undWindowsElementState -ElementId $currentElementId -IncludeRemoved
            if ($null -eq $currentState) {
                Write-Error "[ERROR] ElementId '$currentElementId' was not found in Windows inventory state."
                continue
            }

            if ([string]$currentState.Status -eq 'Removed') {
                Write-Warning "[WARNING] ElementId '$currentElementId' is removed. Re-deploy instead of update."
                continue
            }

            $typeDefinition = Get-PrivateF4keH0undElementTypeDefinition -ElementType ([string]$currentState.DecoyType)
            if ($null -eq $typeDefinition) {
                Write-Error "[ERROR] Element type '$($currentState.DecoyType)' is not available in registry."
                continue
            }

            $stateMetadata = Convert-PrivateF4keH0undObjectToHashtable -InputObject $currentState.Metadata
            $existingTemplate = Convert-PrivateF4keH0undObjectToHashtable -InputObject $stateMetadata['TemplateData']
            foreach ($templateKey in $inputTemplateData.Keys) {
                $existingTemplate[$templateKey] = $inputTemplateData[$templateKey]
            }

            $resolvedTags = if ($PSBoundParameters.ContainsKey('Tag')) {
                @($Tag)
            }
            elseif ($stateMetadata.ContainsKey('Tags')) {
                @($stateMetadata['Tags'])
            }
            else {
                @()
            }

            $resolvedComputer = if ($PSBoundParameters.ContainsKey('ComputerName')) {
                if ($ComputerName.Count -gt $processedCount) {
                    [string]$ComputerName[$processedCount]
                }
                else {
                    [string]$ComputerName[0]
                }
            }
            elseif ($stateMetadata.ContainsKey('ComputerName')) {
                [string]$stateMetadata['ComputerName']
            }
            else {
                $null
            }

            if ([string]::IsNullOrWhiteSpace($resolvedComputer)) {
                Write-Error "[ERROR] Unable to resolve target host for ElementId '$currentElementId'."
                $processedCount++
                continue
            }

            $resolvedName = if ($PSBoundParameters.ContainsKey('Name')) {
                $Name
            }
            elseif ($stateMetadata.ContainsKey('ElementName')) {
                [string]$stateMetadata['ElementName']
            }
            else {
                [string]$currentState.Identity
            }

            $telemetryProfile = if ($stateMetadata.ContainsKey('TelemetryProfile')) {
                [string]$stateMetadata['TelemetryProfile']
            }
            elseif ($typeDefinition.TelemetryProfile) {
                [string]$typeDefinition.TelemetryProfile
            }
            else {
                'Windows-Artifact-Baseline'
            }

            $artifactRoot = if ($stateMetadata.ContainsKey('ArtifactRoot') -and -not [string]::IsNullOrWhiteSpace([string]$stateMetadata['ArtifactRoot'])) {
                [string]$stateMetadata['ArtifactRoot']
            }
            elseif (-not [string]::IsNullOrWhiteSpace([string]$currentState.Location)) {
                try {
                    Split-Path -Path ([string]$currentState.Location) -Parent
                }
                catch {
                    $defaults.ArtifactRoot
                }
            }
            else {
                $defaults.ArtifactRoot
            }

            $target = "$resolvedComputer [$($currentState.DecoyType)]"
            $action = "Update Windows deceptive element '$currentElementId'"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    $invokeParams = @{
                        Action           = 'Update'
                        ElementId        = $currentElementId
                        ElementType      = [string]$currentState.DecoyType
                        ElementName      = $resolvedName
                        ElementFamily    = [string]$typeDefinition.Family
                        ComputerName     = $resolvedComputer
                        ArtifactRoot     = $artifactRoot
                        TemplateData     = $existingTemplate
                        Tags             = $resolvedTags
                        TelemetryProfile = $telemetryProfile
                        Port             = $Port
                        UseSSL           = $useSslValue
                        Authentication   = $Authentication
                    }
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $invokeParams['Credential'] = $Credential
                    }

                    $result = Invoke-PrivateF4keH0undWindowsElementLifecycle @invokeParams
                    $deployedRecords.Add($result)

                    $eventMetadata = @{
                        ComputerName      = $resolvedComputer
                        ElementName       = $resolvedName
                        ElementFamily     = [string]$typeDefinition.Family
                        Tags              = $resolvedTags
                        TemplateData      = $existingTemplate
                        DeploymentChannel = 'WinRM/PSRP'
                        TelemetryProfile  = $telemetryProfile
                        ArtifactRoot      = $artifactRoot
                        ArtifactLocations = @($result.Locations)
                        ThrottleLimit     = $ThrottleLimit
                        UpdatedByCommand  = $MyInvocation.MyCommand.Name
                    }

                    if ([string]$typeDefinition.Family -match 'Identity|Token|Credential') {
                        $eventMetadata['TokenPathHints'] = @($result.Locations)
                    }

                    if ([string]$currentState.DecoyType -eq 'CanaryTextTokenPackDecoy') {
                        $eventMetadata['CollectionHookPresets'] = @('CanaryTextPackSysmonFileCreate', 'CanaryTextPackSecurityObjectAccess')
                    }
                    elseif ([string]$currentState.DecoyType -eq 'ServiceCredentialPackDecoy') {
                        $eventMetadata['CollectionHookPresets'] = @('ServiceCredentialPackSysmonFileCreate', 'ServiceCredentialPackSecurityObjectAccess')
                    }
                    elseif ([string]$currentState.DecoyType -eq 'AdminTroubleshootingTokenPackDecoy') {
                        $eventMetadata['CollectionHookPresets'] = @('AdminTroubleshootingPackSysmonFileCreate', 'AdminTroubleshootingPackSecurityObjectAccess')
                    }

                    Write-F4keH0undInventoryEvent -Action 'Update' -Identity $currentElementId -DecoyType ([string]$currentState.DecoyType) -Platform 'Windows' -ObjectType 'Element' -Status $result.Status -Location $result.BasePath -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name
                }
                catch {
                    Write-Warning "[WARNING] Failed updating element '$currentElementId' on '$resolvedComputer'. Error: $($_.Exception.Message)"
                }
            }

            $processedCount++
        }
    }

    end {
        if ($PassThru) {
            return @($deployedRecords)
        }

        return [PSCustomObject]@{
            UpdatedCount = $deployedRecords.Count
            Platform     = 'Windows'
        }
    }
}
