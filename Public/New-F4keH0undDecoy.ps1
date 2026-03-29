<#
.SYNOPSIS
    Creates decoy objects in AD based on opportunities found by the analysis engine.
.DESCRIPTION
    This is the primary deployment function of the F4keH0und module. It first runs the
    analysis engine (Find-F4keH0undOpportunity) to find deception opportunities.
    It fully supports -WhatIf, -Confirm, and a -Credential parameter for operational safety and flexibility.
    At the end of a successful run, it generates a CSV report of all created decoys.
.PARAMETER BloodHoundPath
    The path to the directory containing the unzipped SharpHound JSON files. This is mandatory.
.PARAMETER Server
    Specify a Domain Controller to run all AD commands against. Required for cross-domain operations.
.PARAMETER Credential
    Allows you to run the script as a standard user and provide the credentials of a privileged
    account for the Active Directory operations. Required for cross-domain operations.
.PARAMETER Execute
    A switch parameter that, if present, initiates the interactive deployment workflow.
.EXAMPLE
    PS C:\> New-F4keH0undDecoy -BloodHoundPath C:\BH_Data\ -Execute -Server "DC01.target.local" -Credential (Get-Credential) -WhatIf

    Runs a dry run of the deployment workflow against a specific domain, showing which users would be
    created AND which groups they would be added to.

.EXAMPLE
    PS C:\> New-F4keH0undDecoy -BloodHoundPath C:\BH_Data\ -Execute -Verbose

    Deploy decoys with recycling preference. Will automatically prefer recycling opportunities over creation.

.EXAMPLE
    PS C:\> New-F4keH0undDecoy -BloodHoundPath C:\BH_Data\ -Verbose

    View deployment strategy before execution. Shows which opportunities will recycle vs create,
    without -Execute no changes are made.

.NOTES
    Recycling vs Creation Strategies:

    - RECYCLE Strategy (Preferred):
      * Uses existing disabled/stale AD objects
      * Preserves original RID and creation timestamps
      * Avoids RID anomaly detection by attackers
      * Objects appear legitimately old and forgotten
      * Requires recyclable objects to be available

    - CREATE Strategy (Fallback):
      * Creates new AD objects with fresh RIDs
      * Easier to detect as decoys via RID analysis
      * Used when no suitable recyclable objects exist
      * Function displays warning about RID anomaly risk

    The deployment engine automatically chooses the best strategy based on
    opportunity recommendations from Find-F4keH0undOpportunity.
#>
function New-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'AD')]
        [string]$BloodHoundPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'Azure')]
        [string]$AzureHoundPath,

        [Parameter(ParameterSetName = 'AD')]
        [string]$Server,

        [Parameter(ParameterSetName = 'AD')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$Execute,

        [Parameter()]
        [string]$DecoyPrefix,

        [Parameter()]
        [string]$DecoySuffix
    )

    # Check for recycling function dependencies
    $recyclingFunctionsAvailable = $true
    $requiredFunctions = @('Find-F4keH0undRecyclableObject', 'Set-PrivateADDecoyUser', 'Set-PrivateADDecoyComputer', 'Set-PrivateADDecoyGroup')

    foreach ($funcName in $requiredFunctions) {
        if (-not (Get-Command -Name $funcName -ErrorAction SilentlyContinue)) {
            Write-Warning "[$($MyInvocation.MyCommand)] - Recycling function '$funcName' not found. Recycling features may not work."
            $recyclingFunctionsAvailable = $false
        }
    }

    if (-not $recyclingFunctionsAvailable) {
        Write-Warning "[$($MyInvocation.MyCommand)] - Some recycling functions are missing. Only creation-based deployment will be available."
    }

    # Load configuration
    $deployConfig = Get-F4keH0undConfig -Section 'DeploymentSettings'

    # Apply deployment settings from config if not specified
    if (-not $PSBoundParameters.ContainsKey('DecoyPrefix') -and $deployConfig.DefaultDecoyPrefix) {
        $DecoyPrefix = $deployConfig.DefaultDecoyPrefix
        Write-Verbose "[$($MyInvocation.MyCommand)] - Using configured DecoyPrefix: '$DecoyPrefix'"
    }

    if (-not $PSBoundParameters.ContainsKey('DecoySuffix') -and $deployConfig.DefaultDecoySuffix) {
        $DecoySuffix = $deployConfig.DefaultDecoySuffix
        Write-Verbose "[$($MyInvocation.MyCommand)] - Using configured DecoySuffix: '$DecoySuffix'"
    }

    # Section 1: Suggest - Run the analysis engine
    Write-Host "--- Running Analysis ---" -ForegroundColor Cyan
    $analysisParams = @{}
    if ($PSCmdlet.ParameterSetName -eq 'AD') { $analysisParams['BloodHoundPath'] = $BloodHoundPath }
    elseif ($PSCmdlet.ParameterSetName -eq 'Azure') { $analysisParams['AzureHoundPath'] = $AzureHoundPath }
    $opportunities = Find-F4keH0undOpportunity @analysisParams
    if (-not $opportunities) {
        Write-Host "[INFO] No opportunities found. Exiting." -ForegroundColor Green
        return
    }

    Write-Host "`n[INFO] Analysis complete. The following opportunities were found:" -ForegroundColor Cyan

    # Format table with Strategy column highlighted
    $opportunities | ForEach-Object {
        $color = if ($_.Strategy -eq 'Recycle') { 'Cyan' } else { 'Yellow' }
        $strategyLabel = if ($_.Strategy -eq 'Recycle') { '[RECYCLE]' } else { '[CREATE]' }
        $rankColor = switch ($_.Rank) {
            'Critical' { 'Red' }
            'High'     { 'DarkRed' }
            'Medium'   { 'Yellow' }
            'Low'      { 'Gray' }
            default    { 'White' }
        }

        Write-Host "$($_.ID): " -NoNewline -ForegroundColor White
        Write-Host "$strategyLabel " -NoNewline -ForegroundColor $color
        Write-Host "$($_.DecoyType) - " -NoNewline -ForegroundColor White
        Write-Host "$($_.Rank) " -NoNewline -ForegroundColor $rankColor
        Write-Host "- $($_.Justification)" -ForegroundColor Gray
    }

    Write-Host "`nLegend:" -ForegroundColor White
    Write-Host "  [RECYCLE] = Uses existing stale object (RID-anomaly safe)" -ForegroundColor Cyan
    Write-Host "  [CREATE]  = Creates new object (RID anomaly risk)" -ForegroundColor Yellow

    if (-not $Execute) {
        Write-Host "`n[INFO] Run this command with the -Execute switch to start the interactive deployment workflow." -ForegroundColor Yellow
        return
    }

    # Section 2: Approve - Handle user interaction
    $selection = Read-Host "`n[PROMPT] Enter the IDs of the decoys you wish to create (e.g., '0,2,5' or 'all'), or press Enter to cancel"
    if ([string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "[INFO] Operation cancelled by user." -ForegroundColor Yellow
        return
    }
    $selectedIds = if ($selection -eq 'all') { $opportunities.ID } else { $selection -split ',' | ForEach-Object { $_.Trim() } }
    $selectedOpportunities = $opportunities | Where-Object { $selectedIds -contains $_.ID }
    if (-not $selectedOpportunities) {
        Write-Error "[ERROR] No valid opportunities selected. Please check the IDs and try again."
        return
    }
    Write-Host "`n--- Deployment Summary ---" -ForegroundColor Cyan
    Write-Host "The following decoys will be deployed:"
    $selectedOpportunities | Format-Table -AutoSize | Out-Host

    # Section 3: Create - Loop and process selected decoys
    $deployedDecoys = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($opportunity in $selectedOpportunities) {
        $target = "$($opportunity.DecoyType) [$($opportunity.Strategy)]"
        $action = "Deploy Decoy"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            $createdObject = $null
            Write-Verbose "[$($MyInvocation.MyCommand)] - Processing Opportunity ID $($opportunity.ID) - $($opportunity.DecoyType) [$($opportunity.Strategy)]"
            switch ($opportunity.DecoyType) {
                "StaleAdminLure" {
                    if ($opportunity.Strategy -eq "Recycle") {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [RECYCLE] Using existing user: $($opportunity.RecyclableObject.SamAccountName)"

                        $params = @{
                            ExistingUser = $opportunity.RecyclableObject
                            Description  = $opportunity.Template.Description
                            ErrorAction  = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = Set-PrivateADDecoyUser @params

                        if ($createdObject) {
                            Write-Host "[RECYCLED] User '$($createdObject.SamAccountName)' (RID: $($createdObject.SID.Value.Split('-')[-1]), Created: $($createdObject.whenCreated))" -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [CREATE] Creating new user (no recyclable objects available)"
                        Write-Warning "[RID ANOMALY RISK] Creating new user - attackers may detect fresh RID value"

                        $decoyName = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"
                        $decoySAM = "$($DecoyPrefix)$($opportunity.Template.SamAccountName)$($DecoySuffix)"

                        $params = @{
                            Name           = $decoyName
                            SamAccountName = $decoySAM
                            Description    = $opportunity.Template.Description
                            ErrorAction    = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = New-PrivateADDecoyUser @params

                        if ($createdObject) {
                            Write-Host "[CREATED] User '$($createdObject.SamAccountName)' (NEW RID: $($createdObject.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow
                        }
                    }

                    # Group membership logic (common to both strategies)
                    if ($createdObject -and $opportunity.Template.GroupsToAdd) {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - Adding decoy to recommended groups..."
                        foreach ($group in $opportunity.Template.GroupsToAdd) {
                            $relationshipParams = @{
                                Decoy            = $createdObject
                                Target           = $group
                                RelationshipType = 'GroupMembership'
                                Environment      = 'AD'
                            }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $relationshipParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $relationshipParams['Server'] = $Server }

                            Add-F4keH0undRelationship @relationshipParams
                        }
                    }
                }
                "KerberoastableUser" {
                    if ($opportunity.Strategy -eq "Recycle") {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [RECYCLE] Using existing user: $($opportunity.RecyclableObject.SamAccountName)"

                        $userParams = @{
                            ExistingUser         = $opportunity.RecyclableObject
                            Description          = $opportunity.Template.Description
                            ServicePrincipalName = $opportunity.Template.ServicePrincipalName
                            ErrorAction          = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }

                        $createdObject = Set-PrivateADDecoyUser @userParams

                        if ($createdObject) {
                            Write-Host "[RECYCLED] Kerberoastable user '$($createdObject.SamAccountName)' with SPN '$($opportunity.Template.ServicePrincipalName)' (RID: $($createdObject.SID.Value.Split('-')[-1]), Created: $($createdObject.whenCreated))" -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [CREATE] Creating new Kerberoastable user"
                        Write-Warning "[RID ANOMALY RISK] Creating new service account - attackers may detect fresh RID value"

                        $decoyName = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"
                        $decoySAM = "$($DecoyPrefix)$($opportunity.Template.SamAccountName)$($DecoySuffix)"

                        $userParams = @{
                            Name           = $decoyName
                            SamAccountName = $decoySAM
                            Description    = $opportunity.Template.Description
                            ErrorAction    = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }

                        $baseUser = New-PrivateADDecoyUser @userParams

                        if ($baseUser) {
                            $spnParams = @{
                                User                 = $baseUser
                                ServicePrincipalName = $opportunity.Template.ServicePrincipalName
                                ErrorAction          = 'Stop'
                            }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $spnParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $spnParams['Server'] = $Server }

                            $spnSuccess = Set-PrivateADDecoySPN @spnParams
                            if ($spnSuccess) {
                                $createdObject = $baseUser
                                Write-Host "[CREATED] Kerberoastable user '$($baseUser.SamAccountName)' with SPN (NEW RID: $($baseUser.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                "UnconstrainedDelegationComputer" {
                    if ($opportunity.Strategy -eq "Recycle") {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [RECYCLE] Using existing computer: $($opportunity.RecyclableObject.Name)"

                        $params = @{
                            ExistingComputer              = $opportunity.RecyclableObject
                            Description                   = $opportunity.Template.Description
                            EnableUnconstrainedDelegation = $true
                            ErrorAction                   = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = Set-PrivateADDecoyComputer @params

                        if ($createdObject) {
                            Write-Host "[RECYCLED] Computer '$($createdObject.Name)' with Unconstrained Delegation (RID: $($createdObject.SID.Value.Split('-')[-1]), Created: $($createdObject.whenCreated))" -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [CREATE] Creating new computer with Unconstrained Delegation"
                        Write-Warning "[RID ANOMALY RISK] Creating new computer - attackers may detect fresh RID value"

                        $decoyName = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"

                        $params = @{
                            Name        = $decoyName
                            Description = $opportunity.Template.Description
                            ErrorAction = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = New-PrivateADDecoyComputer @params

                        if ($createdObject) {
                            Write-Host "[CREATED] Computer '$($createdObject.Name)' with Unconstrained Delegation (NEW RID: $($createdObject.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow
                        }
                    }
                }
                "DNSAdminUser" {
                    if ($opportunity.Strategy -eq "Recycle") {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [RECYCLE] Using existing user: $($opportunity.RecyclableObject.SamAccountName)"

                        $params = @{
                            ExistingUser = $opportunity.RecyclableObject
                            Description  = $opportunity.Template.Description
                            ErrorAction  = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = Set-PrivateADDecoyUser @params

                        if ($createdObject) {
                            Write-Host "[RECYCLED] DNSAdmin user '$($createdObject.SamAccountName)' (RID: $($createdObject.SID.Value.Split('-')[-1]), Created: $($createdObject.whenCreated))" -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [CREATE] Creating new DNSAdmin user"
                        Write-Warning "[RID ANOMALY RISK] Creating new user for DnsAdmins group"

                        $decoyName = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"
                        $decoySAM = "$($DecoyPrefix)$($opportunity.Template.SamAccountName)$($DecoySuffix)"

                        $params = @{
                            Name           = $decoyName
                            SamAccountName = $decoySAM
                            Description    = $opportunity.Template.Description
                            ErrorAction    = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }

                        $createdObject = New-PrivateADDecoyUser @params

                        if ($createdObject) {
                            Write-Host "[CREATED] DNSAdmin user '$($createdObject.SamAccountName)' (NEW RID: $($createdObject.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow
                        }
                    }

                    # Add to DnsAdmins group (common to both strategies)
                    if ($createdObject -and $opportunity.Template.GroupsToAdd) {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - Adding decoy to DnsAdmins group..."
                        foreach ($group in $opportunity.Template.GroupsToAdd) {
                            $relationshipParams = @{
                                Decoy            = $createdObject
                                Target           = $group
                                RelationshipType = 'GroupMembership'
                                Environment      = 'AD'
                            }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $relationshipParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $relationshipParams['Server'] = $Server }

                            Add-F4keH0undRelationship @relationshipParams
                        }
                    }
                }
                "ACLAttackPath" {
                    if ($opportunity.Strategy -eq "Recycle") {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [RECYCLE] Using existing user and group for ACL attack path"

                        $userParams = @{
                            ExistingUser = $opportunity.RecyclableObject.User
                            Description  = "Temporary Helpdesk Account"
                            ErrorAction  = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }

                        $decoyUser = Set-PrivateADDecoyUser @userParams

                        if ($decoyUser) {
                            Write-Host "[RECYCLED] ACL attack path user '$($decoyUser.SamAccountName)' (RID: $($decoyUser.SID.Value.Split('-')[-1]), Created: $($decoyUser.whenCreated))" -ForegroundColor Cyan

                            $groupParams = @{
                                ExistingGroup = $opportunity.RecyclableObject.Group
                                Description   = "Application Administrators for Tier2"
                                ErrorAction   = 'Stop'
                            }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $groupParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $groupParams['Server'] = $Server }

                            $decoyGroup = Set-PrivateADDecoyGroup @groupParams

                            if ($decoyGroup) {
                                Write-Host "[RECYCLED] ACL attack path group '$($decoyGroup.Name)' (RID: $($decoyGroup.SID.Value.Split('-')[-1]), Created: $($decoyGroup.whenCreated))" -ForegroundColor Cyan

                                $aclParams = @{
                                    TargetObject = $decoyGroup
                                    Principal    = $decoyUser
                                    Permission   = $opportunity.Template.Permission
                                    ErrorAction  = 'Stop'
                                }
                                if ($PSBoundParameters.ContainsKey('Credential')) { $aclParams['Credential'] = $Credential }
                                if ($PSBoundParameters.ContainsKey('Server')) { $aclParams['Server'] = $Server }

                                $aclSuccess = Set-PrivateADACL @aclParams

                                if ($aclSuccess) {
                                    $createdObject = $decoyGroup
                                    Write-Host "[SUCCESS] Synthetic ACL attack path created: '$($decoyUser.SamAccountName)' --[WriteMembers]--> '$($decoyGroup.Name)'" -ForegroundColor Green
                                }
                            }
                        }
                    }
                    else {
                        Write-Verbose "[$($MyInvocation.MyCommand)] - [CREATE] Creating new user and group for ACL attack path"
                        Write-Warning "[RID ANOMALY RISK] Creating new objects for ACL attack path"

                        $userName = "$($DecoyPrefix)$($opportunity.Template.DecoyUserName)$($DecoySuffix)"
                        $groupName = "$($DecoyPrefix)$($opportunity.Template.DecoyGroupName)$($DecoySuffix)"

                        $userParams = @{
                            Name           = $userName
                            SamAccountName = $userName
                            Description    = "Temporary Helpdesk Account"
                            ErrorAction    = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }

                        $decoyUser = New-PrivateADDecoyUser @userParams

                        if ($decoyUser) {
                            Write-Host "[CREATED] ACL attack path user '$($userName)' (NEW RID: $($decoyUser.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow

                            $groupParams = @{
                                Name        = $groupName
                                Description = "Application Administrators for Tier2"
                                ErrorAction = 'Stop'
                            }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $groupParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $groupParams['Server'] = $Server }

                            $decoyGroup = New-PrivateADDecoyGroup @groupParams

                            if ($decoyGroup) {
                                Write-Host "[CREATED] ACL attack path group '$($groupName)' (NEW RID: $($decoyGroup.SID.Value.Split('-')[-1]))" -ForegroundColor Yellow

                                $aclParams = @{
                                    TargetObject = $decoyGroup
                                    Principal    = $decoyUser
                                    Permission   = $opportunity.Template.Permission
                                    ErrorAction  = 'Stop'
                                }
                                if ($PSBoundParameters.ContainsKey('Credential')) { $aclParams['Credential'] = $Credential }
                                if ($PSBoundParameters.ContainsKey('Server')) { $aclParams['Server'] = $Server }

                                $aclSuccess = Set-PrivateADACL @aclParams

                                if ($aclSuccess) {
                                    $createdObject = $decoyGroup
                                    Write-Host "[SUCCESS] Synthetic ACL attack path created" -ForegroundColor Green
                                }
                            }
                        }
                    }
                }
            }
            if ($createdObject) {
                Write-Host "[SUCCESS] Successfully deployed decoy '$($createdObject.Name)' and its relationships." -ForegroundColor Green
                $deployedDecoy = [PSCustomObject]@{
                    Object      = $createdObject
                    Opportunity = $opportunity
                    Groups      = @()
                }
                $deployedDecoys.Add($deployedDecoy)
            } else {
                Write-Warning "[FAILURE] Failed to deploy decoy for Opportunity ID $($opportunity.ID)."
            }
        }
    }

    # =================================================================
    # Section 4: Report - Generate the handover file
    # =================================================================
    if ($deployedDecoys.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        # Use configured report path if available
        $reportPath = if ($deployConfig.ReportOutputPath) {
            if (-not (Test-Path $deployConfig.ReportOutputPath)) {
                New-Item -Path $deployConfig.ReportOutputPath -ItemType Directory -Force | Out-Null
            }
            Join-Path -Path $deployConfig.ReportOutputPath -ChildPath "F4keH0und_Deployment_Report_$timestamp.csv"
        }
        else {
            Join-Path -Path $PWD -ChildPath "F4keH0und_Deployment_Report_$timestamp.csv"
        }

        $reportData = $deployedDecoys | ForEach-Object {
            # Extract RID from SID
            $rid = if ($_.Object.SID) { $_.Object.SID.Value.Split('-')[-1] } else { 'N/A' }

            # Determine if object was recycled or created
            $strategy = if ($_.Opportunity.Strategy) { $_.Opportunity.Strategy } else { 'Create' }

            # Calculate age if whenCreated exists
            $ageInDays = if ($_.Object.whenCreated) {
                [math]::Round(((Get-Date) - $_.Object.whenCreated).TotalDays)
            } else {
                'N/A'
            }

            [PSCustomObject]@{
                Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Strategy          = $strategy
                DecoyType         = $_.Opportunity.DecoyType
                Identity          = if ($_.Object.SamAccountName) { $_.Object.SamAccountName } else { $_.Object.Name }
                DistinguishedName = $_.Object.DistinguishedName
                RID               = $rid
                WhenCreated       = if ($_.Object.whenCreated) { $_.Object.whenCreated.ToString('yyyy-MM-dd') } else { 'N/A' }
                AgeInDays         = $ageInDays
                Description       = $_.Object.Description
                Groups            = if ($_.Groups) { $_.Groups -join '; ' } else { '' }
                SPNs              = if ($_.Object.ServicePrincipalNames) { $_.Object.ServicePrincipalNames -join '; ' } else { '' }
                Justification     = $_.Opportunity.Justification
                RIDAnomalySafe    = if ($strategy -eq 'Recycle') { 'Yes' } else { 'No' }
            }
        }

        Write-Host "`n--- Deployment Report ---" -ForegroundColor Cyan
        $reportData | Format-Table -AutoSize | Out-Host

        $confirmSave = Read-Host "`n[PROMPT] Save this report to a CSV file? (y/n)"
        if ($confirmSave -eq 'y') {
            try {
                $reportData | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
                Write-Host "[REPORT] Deployment report saved to: $reportPath" -ForegroundColor Green
                Write-Host "`nSummary:" -ForegroundColor Cyan
                Write-Host "  Total decoys deployed: $($deployedDecoys.Count)" -ForegroundColor Cyan
                Write-Host "  Recycled objects: $(($reportData | Where-Object Strategy -eq 'Recycle').Count)" -ForegroundColor Cyan
                Write-Host "  Created objects: $(($reportData | Where-Object Strategy -eq 'Create').Count)" -ForegroundColor Cyan
                Write-Host "  RID-anomaly safe: $(($reportData | Where-Object RIDAnomalySafe -eq 'Yes').Count)" -ForegroundColor Green
            }
            catch { Write-Error "[ERROR] Failed to save report. Error: $($_.Exception.Message)" }
        }
    } else {
        Write-Host "`n[INFO] No decoys were deployed in this run." -ForegroundColor Yellow
    }
}
