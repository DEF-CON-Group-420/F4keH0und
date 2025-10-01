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
    Write-Host "[INFO] Analysis complete. The following opportunities were found:" -ForegroundColor Cyan
    $opportunities | Format-Table -AutoSize
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
    Write-Host "The following decoys will be created:"
    $selectedOpportunities | Format-Table -AutoSize

    # =================================================================
    # Section 3: Create - Loop and process selected decoys
    # =================================================================
    
    # --- THIS LINE HAS BEEN MOVED to its correct location ---
    $reportRecords = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($opportunity in $selectedOpportunities) {
        $decoySAM = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"
        $decoyName = $decoySAM
        $target = "$($opportunity.DecoyType) '$($decoyName)'"
        $action = "Deploy Decoy"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            $createdObject = $null
            Write-Verbose "Processing Opportunity ID $($opportunity.ID) - $($opportunity.DecoyType)"
            switch ($opportunity.DecoyType) {
                "StaleAdminUser" {
                    $params = @{ Name = $decoyName; SamAccountName = $decoySAM; Description = $opportunity.Template.Description }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }
                    $createdObject = New-PrivateADDecoyUser @params
                    if ($createdObject -and $opportunity.Template.GroupsToAdd) {
                        Write-Verbose "Adding decoy to recommended groups..."
                        foreach ($group in $opportunity.Template.GroupsToAdd) {
                            $relationshipParams = @{ Decoy = $createdObject; Target = $group; RelationshipType = 'GroupMembership'; Environment = 'AD' }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $relationshipParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $relationshipParams['Server'] = $Server }
                            Add-F4keH0undRelationship @relationshipParams
                        }
                    }
                }
                "KerberoastableUser" {
                    $userParams = @{ Name = $decoyName; SamAccountName = $decoySAM; Description = $opportunity.Template.Description }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }
                    $baseUser = New-PrivateADDecoyUser @userParams
                    if ($baseUser) {
                        $spnParams = @{ User = $baseUser; ServicePrincipalName = $opportunity.Template.ServicePrincipalName }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $spnParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $spnParams['Server'] = $Server }
                        $spnSuccess = Set-PrivateADDecoySPN @spnParams
                        if ($spnSuccess) { $createdObject = $baseUser }
                    }
                }
                "UnconstrainedDelegationComputer" {
                    $params = @{ Name = $decoyName; Description = $opportunity.Template.Description }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }
                    $createdObject = New-PrivateADDecoyComputer @params
                }
                "DNSAdminUser" {
                    $params = @{ Name = $decoyName; SamAccountName = $decoySAM; Description = $opportunity.Template.Description }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }
                    $createdObject = New-PrivateADDecoyUser @params
                    if ($createdObject -and $opportunity.Template.GroupsToAdd) {
                        Write-Verbose "Adding decoy to DnsAdmins group..."
                        foreach ($group in $opportunity.Template.GroupsToAdd) {
                            $relationshipParams = @{ Decoy = $createdObject; Target = $group; RelationshipType = 'GroupMembership'; Environment = 'AD' }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $relationshipParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $relationshipParams['Server'] = $Server }
                            Add-F4keH0undRelationship @relationshipParams
                        }
                    }
                }
                "ACLAttackPath" {
                    $userName = "$($DecoyPrefix)$($opportunity.Template.DecoyUserName)$($DecoySuffix)"
                    $groupName = "$($DecoyPrefix)$($opportunity.Template.DecoyGroupName)$($DecoySuffix)"
                    $userParams = @{ Name = $userName; SamAccountName = $userName; Description = "Temporary Helpdesk Account" }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }
                    $decoyUser = New-PrivateADDecoyUser @userParams
                    if ($decoyUser) {
                        $groupParams = @{ Name = $groupName; Description = "Application Administrators for Tier2" }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $groupParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $groupParams['Server'] = $Server }
                        $decoyGroup = New-PrivateADDecoyGroup @groupParams
                        if ($decoyGroup) {
                            $aclParams = @{ TargetObject = $decoyGroup; Principal = $decoyUser; Permission = "WriteMembers" }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $aclParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $aclParams['Server'] = $Server }
                            $aclSuccess = Set-PrivateADACL @aclParams
                            if ($aclSuccess) {
                                $createdObject = $decoyGroup
                            }
                        }
                    }
                }
            }
            if ($createdObject) {
                Write-Host "[SUCCESS] Successfully deployed decoy '$($createdObject.Name)' and its relationships." -ForegroundColor Green
                $record = [PSCustomObject]@{
                    TimestampUTC      = (Get-Date).ToUniversalTime().ToString('u')
                    DecoyName         = $createdObject.Name; DecoyType = $opportunity.DecoyType
                    ObjectSID         = $createdObject.SID.Value; DistinguishedName = $createdObject.DistinguishedName
                    Justification     = $opportunity.Justification
                }
                $reportRecords.Add($record)
            } else {
                Write-Warning "[FAILURE] Failed to create decoy for Opportunity ID $($opportunity.ID)."
            }
        }
    }

    # =================================================================
    # Section 4: Report - Generate the handover file
    # =================================================================
    if ($reportRecords.Count > 0) {
        Write-Host "`n--- Deployment Report ---" -ForegroundColor Cyan
        $reportRecords | Format-Table -AutoSize

        $confirmSave = Read-Host "`n[PROMPT] Save this report to a CSV file? (y/n)"
        if ($confirmSave -eq 'y') {
            $dateString = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $fileName = "F4keH0und-Report-$($dateString).csv"
            $filePath = Join-Path -Path (Get-Location) -ChildPath $fileName
            try {
                $reportRecords | Export-Csv -Path $filePath -NoTypeInformation -ErrorAction Stop
                Write-Host "[SUCCESS] Report saved to '$filePath'" -ForegroundColor Green
            }
            catch { Write-Error "[ERROR] Failed to save report. Error: $($_.Exception.Message)" }
        }
    } else {
        Write-Host "`n[INFO] No decoys were created in this run." -ForegroundColor Yellow
    }
}
