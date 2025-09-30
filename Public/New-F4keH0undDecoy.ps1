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

    # ... (Sections 1 and 2 are unchanged) ...
    # Section 3: Create - Loop and process selected decoys
    $reportRecords = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($opportunity in $selectedOpportunities) {
        # Note: Name construction is handled inside the switch for ACL path
        $decoySAM = "$($DecoyPrefix)$($opportunity.Template.Name)$($DecoySuffix)"
        $decoyName = $decoySAM
        $target = "$($opportunity.DecoyType) '$($decoyName)'"
        $action = "Deploy Decoy"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            $createdObject = $null
            Write-Verbose "Processing Opportunity ID $($opportunity.ID) - $($opportunity.DecoyType)"
            switch ($opportunity.DecoyType) {
                "StaleAdminUser" {
                    # ... existing code ...
                }
                "KerberoastableUser" {
                    # ... existing code ...
                }
                "UnconstrainedDelegationComputer" {
                    # ... existing code ...
                }
                "DNSAdminUser" {
                    # ... existing code ...
                }
                # NEW CASE
                "ACLAttackPath" {
                    $userName = "$($DecoyPrefix)$($opportunity.Template.DecoyUserName)$($DecoySuffix)"
                    $groupName = "$($DecoyPrefix)$($opportunity.Template.DecoyGroupName)$($DecoySuffix)"

                    # Step 1: Create the decoy user
                    $userParams = @{ Name = $userName; SamAccountName = $userName; Description = "Temporary Helpdesk Account" }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $userParams['Credential'] = $Credential }
                    if ($PSBoundParameters.ContainsKey('Server')) { $userParams['Server'] = $Server }
                    $decoyUser = New-PrivateADDecoyUser @userParams

                    if ($decoyUser) {
                        # Step 2: Create the decoy group
                        $groupParams = @{ Name = $groupName; Description = "Application Administrators for Tier2" }
                        if ($PSBoundParameters.ContainsKey('Credential')) { $groupParams['Credential'] = $Credential }
                        if ($PSBoundParameters.ContainsKey('Server')) { $groupParams['Server'] = $Server }
                        $decoyGroup = New-PrivateADDecoyGroup @groupParams

                        if ($decoyGroup) {
                            # Step 3: Set the malicious ACL
                            $aclParams = @{ TargetObject = $decoyGroup; Principal = $decoyUser; Permission = "WriteMembers" }
                            if ($PSBoundParameters.ContainsKey('Credential')) { $aclParams['Credential'] = $Credential }
                            if ($PSBoundParameters.ContainsKey('Server')) { $aclParams['Server'] = $Server }
                            $aclSuccess = Set-PrivateADACL @aclParams

                            if ($aclSuccess) {
                                # The "created object" for the report will be the target group
                                $createdObject = $decoyGroup
                            }
                        }
                    }
                }
            }
            if ($createdObject) {
                # ... existing reporting logic ...
            } else {
                Write-Warning "[FAILURE] Failed to create decoy for Opportunity ID $($opportunity.ID)."
            }
        }
    }
    # ... (End of Section 3) ...
    # Section 4: Report - Generate the handover file
    if ($reportRecords.Count -gt 0) {
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