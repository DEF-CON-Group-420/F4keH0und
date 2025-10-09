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
    Specifies the file path to the directory containing the AzureHound JSON files.
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
    Author: m3c4n1sm0
    Version: 2.5
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
        if ($PSCmdlet.ParameterSetName -eq 'AD') {
            $data = $null
            try {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Loading Active Directory data from '$BloodHoundPath'."
                $data = Get-F4keH0undData -Path $BloodHoundPath -DataType 'AD' -ErrorAction Stop
            }
            catch { Write-Error "[$($MyInvocation.MyCommand)] - Failed to load BloodHound data. Aborting analysis. Error: $($_.Exception.Message)"; return }
            
            # --- Analysis Logic - Stale Privileged Admins ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Stale Privileged Admins..."
            $privilegedGroupBlacklist = @( "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Server Operators", "Backup Operators", "Account Operators", "Print Operators" )
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
                $safeGroupsToAdd = @()
                if ($admin.MemberOf) {
                    # --- BUG FIX: Correctly look up group names ---
                    $memberOfNames = ($admin.MemberOf | ForEach-Object {
                        $groupDN = $_
                        ($data.Groups.data | Where-Object { $groupDN -eq $_.ObjectIdentifier }).Name
                    })
                    $safeGroup = $memberOfNames | Where-Object { $privilegedGroupBlacklist -notcontains (($_.split('@'))[0]) } | Select-Object -First 1
                    if ($safeGroup) {
                        $safeGroupsToAdd += ($safeGroup -split '@')[0]
                    }
                }
                $opportunityShell = [PSCustomObject]@{ DecoyType = "StaleAdminUser" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++; Rank = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Mimics the real dormant Domain Admin '$($admin.Properties.samaccountname)' (password last set $daysSincePwdSet days ago)."
                    Template      = @{
                        Name = "$($admin.Properties.samaccountname)_backup"; Description = "Legacy Admin Account for $($admin.Properties.samaccountname)"
                        samaccountname = $admin.Properties.samaccountname; GroupsToAdd = $safeGroupsToAdd
                    }
                }
                $allOpportunities.Add($opportunity)
            }
            
            # --- Analysis Logic - Kerberoastable Lures ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Kerberoastable Lure opportunities..."
            $kerberoastableTemplateUser = $data.Users.data | Where-Object { $_.Properties.hasspn -eq $true } | Select-Object -First 1
            if ($null -ne $kerberoastableTemplateUser) {
                $domainName = $kerberoastableTemplateUser.Properties.domain; $decoySPN = "MSSQLSvc/decoy-sql-prod-01.$($domainName):1433"
                $opportunityShell = [PSCustomObject]@{ DecoyType = "KerberoastableUser" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++; Rank = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Creates an attractive Kerberoastable user with a common SPN format (e.g., MSSQLSvc) to detect TTP T1558.003."
                    Template      = @{ Name = "svc_mssql_prod"; Description = "Production SQL Service Account"; ServicePrincipalName = $decoySPN }
                }
                $allOpportunities.Add($opportunity)
            }

            # --- Analysis Logic - Unconstrained Delegation ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Unconstrained Delegation computers..."
            $unconstrainedComputers = $data.Computers.data | Where-Object { $_.Properties.unconstraineddelegation -eq $true }
            foreach ($computer in $unconstrainedComputers) {
                $opportunityShell = [PSCustomObject]@{ DecoyType = "UnconstrainedDelegationComputer" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++; Rank = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Mimics the real server with Unconstrained Delegation '$($computer.Name)' which is a high-value target for credential theft."
                    Template      = @{ Name = ($computer.Properties.name -split '\.')[0] + "_DEV"; Description = "Legacy Dev Server for $($computer.Properties.name)" }
                }
                $allOpportunities.Add($opportunity)
            }
            
            # --- Analysis Logic - DNSAdmins User ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for DNSAdmins privilege escalation path..."
            $dnsAdminsGroup = $data.Groups.data | Where-Object { $_.Name -like "*DNSADMINS@*" } | Select-Object -First 1
            if ($dnsAdminsGroup) {
                $opportunityShell = [PSCustomObject]@{ DecoyType = "DNSAdminUser" }
                $opportunity = [PSCustomObject]@{
                    ID            = $opportunityId++; Rank = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType     = $opportunityShell.DecoyType
                    Justification = "Creates a decoy user and adds it to the highly privileged 'DnsAdmins' group to detect attempts at DLL loading on DNS servers."
                    Template      = @{ Name = "svc_dns_manager"; Description = "DNS Management Service Account"; GroupsToAdd = @(($dnsAdminsGroup.Name -split '@')[0]) }
                }
                $allOpportunities.Add($opportunity)
            }

            # --- Analysis Logic - Fake ACL Attack Path ---
            Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Fake ACL Attack Path opportunity..."
            $opportunityShell = [PSCustomObject]@{ DecoyType = "ACLAttackPath" }
            $opportunity = [PSCustomObject]@{
                ID            = $opportunityId++; Rank = Get-F4keH0undRank -Opportunity $opportunityShell
                DecoyType     = $opportunityShell.DecoyType
                Justification = "Creates a synthetic ACL attack path where a decoy user is given write access to a decoy group, luring attackers who use BloodHound to find ACL vulnerabilities."
                Template      = @{ DecoyUserName = "helpdesk_temp"; DecoyGroupName = "Tier2_App_Admins"; Permission = "WriteMembers" }
            }
            $allOpportunities.Add($opportunity)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Azure') {
            # ... (Azure analysis logic is unchanged) ...
        }
    }
    end {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Analysis complete. Found $($allOpportunities.Count) opportunities."
        $allOpportunities | Sort-Object @{Expression = {$rankOrder[$_.Rank]}}
    }
}
