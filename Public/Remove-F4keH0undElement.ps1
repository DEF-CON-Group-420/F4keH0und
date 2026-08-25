<#
.SYNOPSIS
    Removes deployed Windows artifact deception elements.

.DESCRIPTION
    Deletes Windows artifact decoy paths on target hosts and records lifecycle
    remove events in persistent inventory.

.PARAMETER ElementId
    One or more deployed element identifiers.

.PARAMETER ComputerName
    Optional host override. If omitted, target host is resolved from inventory.

.PARAMETER PurgeTelemetryMap
    Indicates telemetry mapping should be purged. Current implementation records
    this intent in inventory metadata.

.PARAMETER Credential
    Optional credential for WinRM remoting.

.PARAMETER Port
    WinRM port override.

.PARAMETER UseSSL
    Use WinRM over HTTPS.

.PARAMETER Authentication
    WinRM authentication method.

.PARAMETER PassThru
    Returns removal records.
#>
function Remove-F4keH0undElement {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$ElementId,

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [switch]$PurgeTelemetryMap,

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
        [switch]$PassThru
    )

    begin {
        $defaults = Get-PrivateF4keH0undWindowsDeploymentDefaults
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $defaults.Port }
        if (-not $PSBoundParameters.ContainsKey('Authentication')) { $Authentication = $defaults.Authentication }
        $useSslValue = if ($PSBoundParameters.ContainsKey('UseSSL')) { [bool]$UseSSL } else { [bool]$defaults.UseSSL }
        $removedRecords = [System.Collections.Generic.List[PSObject]]::new()
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

            $typeDefinition = Get-PrivateF4keH0undElementTypeDefinition -ElementType ([string]$currentState.DecoyType)
            if ($null -eq $typeDefinition) {
                Write-Error "[ERROR] Element type '$($currentState.DecoyType)' is not available in registry."
                continue
            }

            $stateMetadata = Convert-PrivateF4keH0undObjectToHashtable -InputObject $currentState.Metadata
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

            $resolvedName = if ($stateMetadata.ContainsKey('ElementName')) {
                [string]$stateMetadata['ElementName']
            }
            else {
                [string]$currentState.Identity
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

            $templateData = Convert-PrivateF4keH0undObjectToHashtable -InputObject $stateMetadata['TemplateData']
            $resolvedTags = if ($stateMetadata.ContainsKey('Tags')) { @($stateMetadata['Tags']) } else { @() }
            $telemetryProfile = if ($stateMetadata.ContainsKey('TelemetryProfile')) { [string]$stateMetadata['TelemetryProfile'] } elseif ($typeDefinition.TelemetryProfile) { [string]$typeDefinition.TelemetryProfile } else { 'Windows-Artifact-Baseline' }

            $target = "$resolvedComputer [$($currentState.DecoyType)]"
            $action = "Remove Windows deceptive element '$currentElementId'"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    $invokeParams = @{
                        Action           = 'Remove'
                        ElementId        = $currentElementId
                        ElementType      = [string]$currentState.DecoyType
                        ElementName      = $resolvedName
                        ElementFamily    = [string]$typeDefinition.Family
                        ComputerName     = $resolvedComputer
                        ArtifactRoot     = $artifactRoot
                        TemplateData     = $templateData
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
                    $removedRecords.Add($result)

                    $eventMetadata = @{
                        ComputerName      = $resolvedComputer
                        ElementName       = $resolvedName
                        ElementFamily     = [string]$typeDefinition.Family
                        Tags              = $resolvedTags
                        TemplateData      = $templateData
                        DeploymentChannel = 'WinRM/PSRP'
                        TelemetryProfile  = $telemetryProfile
                        ArtifactRoot      = $artifactRoot
                        PurgeTelemetryMap = [bool]$PurgeTelemetryMap
                    }

                    Write-F4keH0undInventoryEvent -Action 'Remove' -Identity $currentElementId -DecoyType ([string]$currentState.DecoyType) -Platform 'Windows' -ObjectType 'Element' -Status 'Removed' -Location $result.BasePath -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name
                }
                catch {
                    Write-Warning "[WARNING] Failed removing element '$currentElementId' on '$resolvedComputer'. Error: $($_.Exception.Message)"
                }
            }

            $processedCount++
        }
    }

    end {
        if ($PassThru) {
            return @($removedRecords)
        }

        return [PSCustomObject]@{
            RemovedCount = $removedRecords.Count
            Platform     = 'Windows'
        }
    }
}
