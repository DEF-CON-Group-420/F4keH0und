<#
.SYNOPSIS
    Plans or executes Entra deployments to close AD/Entra coverage parity gaps.

.DESCRIPTION
    Uses `Test-F4keH0undCoverage` to identify family-level parity gaps, discovers
    Entra opportunities, and optionally deploys recyclable Entra decoys directly
    through `Set-PrivateEntraDecoyPrincipal`.

    This command is PowerShell-first and cross-platform friendly. It requires a
    connected Microsoft Graph session for `-Execute` mode.

.PARAMETER AzureHoundPath
    Path to AzureHound data used for Entra opportunity discovery.

.PARAMETER Source
    Inventory source used for parity baseline.

.PARAMETER IncludeRemoved
    Includes removed inventory entries when building baseline state.

.PARAMETER PreferSnapshot
    Prefer snapshot cache before event replay for events source.

.PARAMETER SkipLiveStatus
    Skips live AD status checks during parity baseline calculation.

.PARAMETER Server
    Optional Domain Controller for AD live status checks.

.PARAMETER Credential
    Optional credential for AD live status checks.

.PARAMETER TargetParityRatio
    Required Entra-to-AD family ratio. `1.0` means equal active Entra vs AD
    decoys per mapped family.

.PARAMETER MaxDeployments
    Maximum number of Entra decoys to deploy in one run when `-Execute` is used.

.PARAMETER Execute
    Applies the recommended Entra parity deployments.

.PARAMETER AuditLogPath
    Optional NDJSON audit log target passed to Entra recycling helper.

.PARAMETER EntraIncludeServicePrincipals
    Include service-principal Entra opportunities.

.PARAMETER EntraIncludeGuestUsers
    Include guest-user Entra opportunities.

.PARAMETER EntraIncludeAppRegistrations
    Include app-registration Entra opportunities.

.PARAMETER EntraRecyclingMinimumAgeDays
    Minimum age for recyclable Entra objects.

.PARAMETER EntraRecyclingMaximumAgeDays
    Maximum age for recyclable Entra objects.

.PARAMETER EntraPreferRecycling
    Boosts rank for recycling opportunities in Entra analysis.

.PARAMETER EntraRecyclingOnly
    Restricts Entra analysis to recycling opportunities.

.PARAMETER PassThru
    Returns deployed object records when `-Execute` is used.

.EXAMPLE
    Sync-F4keH0undEntraParity -AzureHoundPath ./AzureHound_Data

.EXAMPLE
    Sync-F4keH0undEntraParity -AzureHoundPath ./AzureHound_Data -Execute -MaxDeployments 3 -WhatIf
#>
function Sync-F4keH0undEntraParity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AzureHoundPath,

        [Parameter()]
        [ValidateSet('Auto', 'Events', 'Reports')]
        [string]$Source = 'Auto',

        [Parameter()]
        [switch]$IncludeRemoved,

        [Parameter()]
        [switch]$PreferSnapshot,

        [Parameter()]
        [switch]$SkipLiveStatus,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(0, 10)]
        [double]$TargetParityRatio = 1.0,

        [Parameter()]
        [ValidateRange(1, 250)]
        [int]$MaxDeployments = 5,

        [Parameter()]
        [switch]$Execute,

        [Parameter()]
        [string]$AuditLogPath,

        [Parameter()]
        [switch]$EntraIncludeServicePrincipals,

        [Parameter()]
        [switch]$EntraIncludeGuestUsers,

        [Parameter()]
        [switch]$EntraIncludeAppRegistrations,

        [Parameter()]
        [int]$EntraRecyclingMinimumAgeDays = 180,

        [Parameter()]
        [int]$EntraRecyclingMaximumAgeDays = 3650,

        [Parameter()]
        [switch]$EntraPreferRecycling,

        [Parameter()]
        [switch]$EntraRecyclingOnly,

        [Parameter()]
        [switch]$PassThru
    )

    $coverageParams = @{
        Source            = $Source
        TargetParityRatio = $TargetParityRatio
    }
    if ($IncludeRemoved) { $coverageParams['IncludeRemoved'] = $true }
    if ($PreferSnapshot) { $coverageParams['PreferSnapshot'] = $true }
    if ($SkipLiveStatus) { $coverageParams['SkipLiveStatus'] = $true }
    if ($PSBoundParameters.ContainsKey('Server')) { $coverageParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $coverageParams['Credential'] = $Credential }

    $coverageBefore = Test-F4keH0undCoverage @coverageParams
    $gapFamilies = @($coverageBefore.FamilyStatus | Where-Object { $_.Gap -gt 0 } | Sort-Object -Property Gap -Descending)

    $parityModel = Get-F4keH0undParityModel
    $familyLookup = @{}
    foreach ($familyDef in $parityModel.FamilyMappings) {
        $familyLookup[[string]$familyDef.Family] = $familyDef
    }

    $opportunityParams = @{
        AzureHoundPath               = $AzureHoundPath
        EntraRecyclingMinimumAgeDays = $EntraRecyclingMinimumAgeDays
        EntraRecyclingMaximumAgeDays = $EntraRecyclingMaximumAgeDays
        ErrorAction                  = 'Stop'
    }
    if ($EntraIncludeServicePrincipals) { $opportunityParams['EntraIncludeServicePrincipals'] = $true }
    if ($EntraIncludeGuestUsers) { $opportunityParams['EntraIncludeGuestUsers'] = $true }
    if ($EntraIncludeAppRegistrations) { $opportunityParams['EntraIncludeAppRegistrations'] = $true }
    if ($EntraPreferRecycling) { $opportunityParams['EntraPreferRecycling'] = $true }
    if ($EntraRecyclingOnly) { $opportunityParams['EntraRecyclingOnly'] = $true }

    $allEntraOpportunities = @()
    try {
        $allEntraOpportunities = @(
            Find-F4keH0undOpportunity @opportunityParams |
                Where-Object {
                    [string]$_.DecoyType -in @('EntraServicePrincipalDecoy', 'EntraGuestUserDecoy', 'EntraAppRegistrationDecoy')
                }
        )
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to discover Entra opportunities for parity sync. Error: $($_.Exception.Message)"
        $allEntraOpportunities = @()
    }

    $rankOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $orderedOpportunities = @(
        $allEntraOpportunities | Sort-Object -Property @{ Expression = {
            $rankName = [string]$_.Rank
            if ($rankOrder.ContainsKey($rankName)) {
                $rankOrder[$rankName]
            }
            else {
                999
            }
        } }, @{ Expression = {
            if ($_.RecyclableObject -and $_.RecyclableObject.PSObject.Properties.Name -contains 'StalenessScore') {
                -[int]$_.RecyclableObject.StalenessScore
            }
            else {
                0
            }
        } }, ID
    )

    $selected = [System.Collections.Generic.List[PSObject]]::new()
    $selectedIds = @{}

    foreach ($gapFamily in $gapFamilies) {
        if ($selected.Count -ge $MaxDeployments) {
            break
        }

        $familyName = [string]$gapFamily.Family
        if (-not $familyLookup.ContainsKey($familyName)) {
            continue
        }

        $familyDef = $familyLookup[$familyName]
        $neededCount = [int]$gapFamily.Gap
        if ($neededCount -le 0) {
            continue
        }

        $familyCandidates = @(
            $orderedOpportunities | Where-Object {
                $familyDef.EntraDecoyTypes -contains [string]$_.DecoyType
            }
        )

        foreach ($candidate in $familyCandidates) {
            if ($selected.Count -ge $MaxDeployments -or $neededCount -le 0) {
                break
            }

            $candidateId = [string]$candidate.ID
            if ($selectedIds.ContainsKey($candidateId)) {
                continue
            }

            $selected.Add($candidate)
            $selectedIds[$candidateId] = $true
            $neededCount--
        }
    }

    $selectedPlan = @(
        $selected | ForEach-Object {
            $selectedDecoyType = [string]$_.DecoyType
            [PSCustomObject]@{
                OpportunityId = $_.ID
                DecoyType     = $selectedDecoyType
                Strategy      = $_.Strategy
                Rank          = $_.Rank
                Family        = ($parityModel.DecoyTypes | Where-Object { $_.DecoyType -eq $selectedDecoyType } | Select-Object -First 1).Family
                IdentityHint  = if ($_.RecyclableObject.DisplayName) { $_.RecyclableObject.DisplayName } else { $_.RecyclableObject.ObjectId }
                Justification = $_.Justification
                LureTheme     = [string]$_.Template.LureTheme
                ConsentScopeBait = [string]$_.Template.ConsentScopeBait
                ConditionalAccessBypassHint = [string]$_.Template.ConditionalAccessBypassHint
            }
        }
    )

    $deployedRecords = [System.Collections.Generic.List[PSObject]]::new()

    if ($Execute -and $selected.Count -gt 0) {
        foreach ($opportunity in $selected) {
            if ($deployedRecords.Count -ge $MaxDeployments) {
                break
            }

            $target = "$($opportunity.DecoyType) [$($opportunity.Strategy)]"
            $action = 'Deploy Entra parity decoy'
            if (-not $PSCmdlet.ShouldProcess($target, $action)) {
                continue
            }

            if (-not $opportunity.RecyclableObject) {
                Write-Warning "[$($MyInvocation.MyCommand)] - Opportunity ID $($opportunity.ID) has no recyclable object and cannot be deployed."
                continue
            }

            try {
                $entraParams = @{
                    RecyclableObject = $opportunity.RecyclableObject
                    Description      = $opportunity.Template.Description
                    ErrorAction      = 'Stop'
                }
                if ($opportunity.DecoyType -eq 'EntraServicePrincipalDecoy' -and $opportunity.Template.AssignHighPrivilegeRole) {
                    $entraParams['AssignHighPrivilegeRole'] = $true
                }
                foreach ($templateKey in @('LureTheme', 'RoleAssignmentHint', 'ConsentScopeBait', 'ConditionalAccessBypassHint', 'SecretHint', 'PersonaJobTitle', 'PersonaDepartment')) {
                    $templateValue = $opportunity.Template.$templateKey
                    if (-not [string]::IsNullOrWhiteSpace([string]$templateValue)) {
                        $entraParams[$templateKey] = [string]$templateValue
                    }
                }
                if ($PSBoundParameters.ContainsKey('AuditLogPath')) {
                    $entraParams['AuditLogPath'] = $AuditLogPath
                }

                $createdObject = Set-PrivateEntraDecoyPrincipal @entraParams

                $objectType = switch ([string]$opportunity.DecoyType) {
                    'EntraServicePrincipalDecoy' { 'ServicePrincipal' }
                    'EntraGuestUserDecoy' { 'GuestUser' }
                    'EntraAppRegistrationDecoy' { 'AppRegistration' }
                    default { 'ServicePrincipal' }
                }

                $updatedObject = Get-PrivateEntraDecoyObjectById -ObjectId $createdObject.ObjectId -ObjectType $objectType
                $eventContext = Get-PrivateEntraDecoyEventContext -ObjectType $objectType -Object $updatedObject

                $eventMetadata = @{
                    OpportunityId = $opportunity.ID
                    Justification = $opportunity.Justification
                    SyncCommand   = $MyInvocation.MyCommand.Name
                }
                foreach ($metadataKey in @('LureTheme', 'RoleAssignmentHint', 'ConsentScopeBait', 'ConditionalAccessBypassHint', 'SecretHint')) {
                    $metadataValue = $opportunity.Template.$metadataKey
                    if (-not [string]::IsNullOrWhiteSpace([string]$metadataValue)) {
                        $eventMetadata[$metadataKey] = [string]$metadataValue
                    }
                }

                Write-F4keH0undInventoryEvent -Action 'Deploy' -Identity $eventContext.Identity -DecoyType $opportunity.DecoyType -Platform 'Entra' -ObjectType $objectType -Strategy $opportunity.Strategy -Status $eventContext.Status -Location $eventContext.Location -Metadata $eventMetadata -SourceCommand $MyInvocation.MyCommand.Name

                $deployedRecords.Add([PSCustomObject]@{
                    OpportunityId = $opportunity.ID
                    DecoyType     = $opportunity.DecoyType
                    ObjectType    = $objectType
                    Identity      = $eventContext.Identity
                    DisplayName   = $eventContext.DisplayName
                    Status        = $eventContext.Status
                    Location      = $eventContext.Location
                })
            }
            catch {
                Write-Warning "[$($MyInvocation.MyCommand)] - Failed deploying opportunity ID $($opportunity.ID). Error: $($_.Exception.Message)"
            }
        }
    }

    $coverageAfter = if ($Execute -and $deployedRecords.Count -gt 0) {
        Test-F4keH0undCoverage @coverageParams
    }
    else {
        $coverageBefore
    }

    $result = [PSCustomObject]@{
        Timestamp             = Get-Date
        Execute               = [bool]$Execute
        TargetParityRatio     = $TargetParityRatio
        MaxDeployments        = $MaxDeployments
        CoverageBefore        = $coverageBefore
        CoverageAfter         = $coverageAfter
        GapFamilies           = @($gapFamilies)
        SelectedOpportunities = @($selectedPlan)
        PlannedCount          = $selectedPlan.Count
        DeployedCount         = $deployedRecords.Count
        Deployed              = @($deployedRecords)
        IsParityMetAfterRun   = [bool]$coverageAfter.IsParityMet
    }

    if ($PassThru -and $Execute) {
        return @($deployedRecords)
    }

    return $result
}
