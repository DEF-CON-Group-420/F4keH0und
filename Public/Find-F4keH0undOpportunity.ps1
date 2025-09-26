<#
.SYNOPSIS
    Analyzes BloodHound and AzureHound data to find deception opportunities.
.DESCRIPTION
    This function is the core of the F4keH0und analysis engine. It parses the JSON output from
    the SharpHound collector to identify and rank potential decoy objects and relationships.
    These suggestions can then be used by New-F4keH0undDecoy to deploy them into Active Directory.
.PARAMETER BloodHoundPath
    Specifies the file path to the directory containing the unzipped SharpHound JSON files.
    This directory must contain files like users.json, groups.json, etc. This parameter is mandatory.
.PARAMETER AzureHoundPath
    Specifies the file path to the directory containing the AzureHound JSON files. This parameter
    is not yet fully implemented for analysis in this version.
.PARAMETER StaleAdminThresholdDays
    Specifies the number of days since the last password set for a privileged account (admincount=1)
    for it to be considered 'stale' and thus a candidate for a decoy. The default value is 365 days.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\Path\To\BloodHound_Data\
    Analyzes the Active Directory data located in the specified folder and returns a ranked list
    of suggested deception opportunities.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\AD_Exports\ -StaleAdminThresholdDays 90 -Verbose
    Analyzes the AD data, considering any admin account with a password older than 90 days
    as stale. It also provides verbose output showing the steps the function is taking during analysis.
.OUTPUTS
    System.Collections.Generic.List[PSObject]
    Returns a list of custom PowerShell objects, where each object represents a single deception opportunity.
.NOTES
    Author: Your Name Here
    Version: 0.1.0
    This function performs a read-only analysis and does not make any changes to your environment.
.LINK
    Get-Help New-F4keH0undDecoy
#>
function Find-F4keH0undOpportunity {
    [CmdletBinding(DefaultParameterSetName = 'AD')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'AD', HelpMessage = "Path to the SharpHound JSON files.")]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$BloodHoundPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'Azure', HelpMessage = "Path to the AzureHound JSON files.")]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$AzureHoundPath,
        [Parameter(ParameterSetName = 'AD')]
        [int]$StaleAdminThresholdDays = 365
    )

    begin {
        $allOpportunities = [System.Collections.Generic.List[PSObject]]::new()
        $opportunityId = 0
        $rankOrder = @{
            "Critical" = 0
            "High"     = 1
            "Medium"   = 2
            "Low"      = 3
        }
    }
    process {
        $data = $null
        try {
            if ($PSCmdlet.ParameterSetName -eq 'AD') {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Loading Active Directory data from '$BloodHoundPath'."
                $data = Get-F4keH0undData -Path $BloodHoundPath -DataType 'AD' -ErrorAction Stop
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Azure') {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Loading Azure data from '$AzureHoundPath'."
                $data = Get-F4keH0undData -Path $AzureHoundPath -DataType 'Azure' -ErrorAction Stop
            }
        }
        catch {
            Write-Error "[$($MyInvocation.MyCommand)] - Failed to load BloodHound data. Aborting analysis. Error: $($_.Exception.Message)"
            return
        }
        if ($PSCmdlet.ParameterSetName -eq 'AD') {
            # --- ON-PREM AD ANALYSIS LOGIC ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Stale Privileged Admins..."
            $staleThresholdDate = (Get-Date).AddDays(-$StaleAdminThresholdDays)
            $staleAdmins = $data.Users.data | Where-Object {
                $_.Properties.enabled -eq $true -and
                $_.Properties.admincount -eq $true -and
                $_.Properties.pwdlastset -ne 0 -and
                ([datetime]::FromFileTime($_.Properties.pwdlastset)) -lt $staleThresholdDate
            }
            foreach ($admin in $staleAdmins) {
                $pwdSetDate = [datetime]::FromFileTime($admin.Properties.pwdlastset)
                $daysSincePwdSet = (New-TimeSpan -Start $pwdSetDate -End (Get-Date)).Days
                $opportunityShell = [PSCustomObject]@{ DecoyType = "StaleAdminUser" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++
                    Rank          = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Mimics the real dormant Domain Admin '$($admin.Properties.samaccountname)' (password last set $daysSincePwdSet days ago)."
                    Template      = @{
                        Name              = "$($admin.Properties.samaccountname)_backup"
                        Description       = "Legacy Admin Account for $($admin.Name)"
                        pwdlastset        = $admin.Properties.pwdlastset
                        samaccountname    = $admin.Properties.samaccountname
                    }
                }
                $allOpportunities.Add($opportunity)
            }
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Kerberoastable Lure opportunities..."
            $kerberoastableTemplateUser = $data.Users.data | Where-Object { $_.Properties.hasspn -eq $true } | Select-Object -First 1
            if ($null -ne $kerberoastableTemplateUser) {
                $domainName = $kerberoastableTemplateUser.Properties.domain
                $decoySPN = "MSSQLSvc/decoy-sql-prod-01.$($domainName):1433"
                $opportunityShell = [PSCustomObject]@{ DecoyType = "KerberoastableUser" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++
                    Rank          = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Creates an attractive Kerberoastable user with a common SPN format (e.g., MSSQLSvc) to detect TTP T1558.003."
                    Template      = @{
                        Name           = "svc_mssql_prod"
                        Description    = "Production SQL Service Account"
                        ServicePrincipalName = $decoySPN
                    }
                }
                $allOpportunities.Add($opportunity)
            }
        }
        # =================================================================
        # NEW SECTION: ENTRA ID ANALYSIS LOGIC
        # =================================================================
        elseif ($PSCmdlet.ParameterSetName -eq 'Azure') {
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Over-privileged Entra ID Principals..."
            
            # Define a list of high-privilege role display names to look for
            $highPrivilegeRoles = @(
                "Global Administrator",
                "Privileged Role Administrator",
                "User Administrator",
                "Cloud Application Administrator"
            )

            # Find all service principals that have one of these powerful roles
            $privilegedSPs = $data.ServicePrincipals.data | Where-Object {
                ($_.Roles.DisplayName -as [array]) -and ($_.Roles.DisplayName | Where-Object { $highPrivilegeRoles -contains $_ })
            }

            foreach ($sp in $privilegedSPs) {
                # Find the specific high-privilege role for the justification text
                $assignedRole = $sp.Roles.DisplayName | Where-Object { $highPrivilegeRoles -contains $_ } | Select-Object -First 1

                $opportunityShell = [PSCustomObject]@{ DecoyType = "PrivilegedEntraSP" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++
                    Rank          = "Critical" # Placeholder rank
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Mimics the real '$($assignedRole)' service principal '$($sp.DisplayName)'."
                    Template      = @{
                        Name        = "$($sp.DisplayName)-backup"
                        Description = "Legacy Service Principal for $($sp.DisplayName)"
                    }
                }
                $allOpportunities.Add($opportunity)
            }
        }
    }
    end {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Analysis complete. Found $($allOpportunities.Count) opportunities."
        $allOpportunities | Sort-Object @{Expression = {$rankOrder[$_.Rank]}}
    }
}
