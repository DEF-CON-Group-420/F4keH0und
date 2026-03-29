<#
.SYNOPSIS
    Analyzes BloodHound and AzureHound data to find deception opportunities.
.DESCRIPTION
    This function is the core of the F4keH0und analysis engine. It parses the JSON output from
    the SharpHound collector to identify and rank potential decoy objects and relationships.
    These suggestions can then be used by New-F4keH0undDecoy to deploy them into Active Directory.

    When run in AD mode, the function first scans for recyclable AD objects using
    Find-F4keH0undRecyclableObject and prioritises recycling over creating new objects.
.PARAMETER BloodHoundPath
    Specifies the file path to the directory containing the unzipped SharpHound JSON files.
    This directory must contain files like users.json, groups.json, etc. This parameter is mandatory.
.PARAMETER AzureHoundPath
    Specifies the file path to the directory containing the AzureHound JSON files.
.PARAMETER StaleAdminThresholdDays
    Specifies the number of days since the last password set for a privileged account (admincount=1)
    for it to be considered 'stale' and thus a candidate for a decoy. The default value is 365 days.
.PARAMETER PreferRecycling
    When specified, recycling opportunities are ranked higher than creation opportunities.
    This prioritizes using existing stale AD objects over creating new ones, avoiding RID anomaly detection.
.PARAMETER RecyclingOnly
    When specified, ONLY returns recycling opportunities. If no suitable recyclable objects are found,
    returns an empty array. Use this to enforce a strict "no new objects" policy.
.PARAMETER RecyclingMinimumAgeDays
    Minimum age (in days) for objects to be considered recyclable. Default: 180 days.
    Objects younger than this will not be selected for recycling.
.PARAMETER RecyclingMaximumAgeDays
    Maximum age (in days) for objects to be considered recyclable. Default: 3650 days (~10 years).
    Objects older than this will not be selected (may indicate truly ancient, possibly still-referenced objects).
.PARAMETER ExcludeOUs
    Array of Organizational Unit paths to exclude from recycling candidate search.
    Use this to protect specific OUs from having their objects recycled.
    Example: @("OU=VIP,DC=contoso,DC=local", "OU=Executives,DC=contoso,DC=local")
.PARAMETER Server
    Specify a Domain Controller to run recyclable-object discovery against.
    Required for cross-domain operations.
.PARAMETER Credential
    Allows you to provide credentials for the recyclable-object discovery AD queries.
    Required for cross-domain operations.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\Path\To\BloodHound_Data\
    Analyzes the Active Directory data located in the specified folder and returns a ranked list
    of suggested deception opportunities.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\AD_Exports\ -StaleAdminThresholdDays 90 -Verbose
    Analyzes the AD data, considering any admin account with a password older than 90 days
    as stale. It also provides verbose output showing the steps the function is taking during analysis.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling -Verbose
    Prefer recycling over creation - recycling opportunities are ranked higher.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -RecyclingOnly -RecyclingMinimumAgeDays 365
    Only show recycling opportunities (strict mode). Returns empty array if none found.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling -ExcludeOUs @("OU=VIP,DC=contoso,DC=local")
    Recycling with OU exclusions.
.EXAMPLE
    PS C:\> Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling -Server "DC01.target.local" -Credential $cred
    Cross-domain recycling opportunity discovery.
.OUTPUTS
    System.Collections.Generic.List[PSObject]
    Returns a list of custom PowerShell objects, where each object represents a single deception opportunity.
.NOTES
    Author: m3c4n1sm0
    Version: 3.0
    This function performs a read-only analysis and does not make any changes to your environment.
.LINK
    Get-Help New-F4keH0undDecoy
#>
function Find-F4keH0undOpportunity {
    [CmdletBinding(DefaultParameterSetName = 'AD')]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'AD', HelpMessage = "Path to the SharpHound JSON files.")]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$BloodHoundPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Azure', HelpMessage = "Path to the AzureHound JSON files.")]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$AzureHoundPath,

        [Parameter(ParameterSetName = 'AD')]
        [int]$StaleAdminThresholdDays = 365,

        [Parameter(ParameterSetName = 'AD')]
        [switch]$PreferRecycling,

        [Parameter(ParameterSetName = 'AD')]
        [switch]$RecyclingOnly,

        [Parameter(ParameterSetName = 'AD')]
        [int]$RecyclingMinimumAgeDays = 180,

        [Parameter(ParameterSetName = 'AD')]
        [int]$RecyclingMaximumAgeDays = 3650,

        [Parameter(ParameterSetName = 'AD')]
        [string[]]$ExcludeOUs,

        [Parameter(ParameterSetName = 'AD')]
        [string]$Server,

        [Parameter(ParameterSetName = 'AD')]
        [System.Management.Automation.PSCredential]$Credential
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
        $recyclableUsers = @()
        $recyclableComputers = @()
        $recyclableGroups = @()
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'AD') {
            # Dependency check for recycling support
            $recyclingAvailable = $null -ne (Get-Command -Name Find-F4keH0undRecyclableObject -ErrorAction SilentlyContinue)
            if (-not $recyclingAvailable) {
                Write-Warning "[$($MyInvocation.MyCommand)] - Find-F4keH0undRecyclableObject function not found. Recycling features disabled."
            }

            $data = $null
            try {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Loading Active Directory data from '$BloodHoundPath'."
                $data = Get-F4keH0undData -Path $BloodHoundPath -DataType 'AD' -ErrorAction Stop
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to load BloodHound data. Aborting analysis. Error: $($_.Exception.Message)"
                return
            }

            # ------------------------------------------------------------------
            # Phase 1 - Discover Recyclable Objects
            # ------------------------------------------------------------------
            Write-Verbose "[$($MyInvocation.MyCommand)] - Phase 1: Discovering recyclable AD objects..."

            if ($recyclingAvailable) {
                # Discover recyclable users
                try {
                    $userRecycleParams = @{
                        Type           = 'User'
                        MinimumAgeDays = $RecyclingMinimumAgeDays
                        MaximumAgeDays = $RecyclingMaximumAgeDays
                        MaxResults     = 50
                        ErrorAction    = 'Stop'
                    }
                    if ($PSBoundParameters.ContainsKey('ExcludeOUs')) { $userRecycleParams['ExcludeOUs'] = $ExcludeOUs }
                    if ($PSBoundParameters.ContainsKey('Server'))     { $userRecycleParams['Server']     = $Server }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $userRecycleParams['Credential'] = $Credential }

                    $recyclableUsers = @(Find-F4keH0undRecyclableObject @userRecycleParams)
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($recyclableUsers.Count) recyclable user objects."
                }
                catch {
                    Write-Warning "[$($MyInvocation.MyCommand)] - Failed to discover recyclable users: $($_.Exception.Message)"
                }

                # Discover recyclable computers
                try {
                    $computerRecycleParams = @{
                        Type           = 'Computer'
                        MinimumAgeDays = $RecyclingMinimumAgeDays
                        MaximumAgeDays = $RecyclingMaximumAgeDays
                        MaxResults     = 20
                        ErrorAction    = 'Stop'
                    }
                    if ($PSBoundParameters.ContainsKey('ExcludeOUs')) { $computerRecycleParams['ExcludeOUs'] = $ExcludeOUs }
                    if ($PSBoundParameters.ContainsKey('Server'))     { $computerRecycleParams['Server']     = $Server }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $computerRecycleParams['Credential'] = $Credential }

                    $recyclableComputers = @(Find-F4keH0undRecyclableObject @computerRecycleParams)
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($recyclableComputers.Count) recyclable computer objects."
                }
                catch {
                    Write-Warning "[$($MyInvocation.MyCommand)] - Failed to discover recyclable computers: $($_.Exception.Message)"
                }

                # Discover recyclable groups
                try {
                    $groupRecycleParams = @{
                        Type           = 'Group'
                        MinimumAgeDays = $RecyclingMinimumAgeDays
                        MaximumAgeDays = $RecyclingMaximumAgeDays
                        MaxResults     = 20
                        ErrorAction    = 'Stop'
                    }
                    if ($PSBoundParameters.ContainsKey('ExcludeOUs')) { $groupRecycleParams['ExcludeOUs'] = $ExcludeOUs }
                    if ($PSBoundParameters.ContainsKey('Server'))     { $groupRecycleParams['Server']     = $Server }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $groupRecycleParams['Credential'] = $Credential }

                    $recyclableGroups = @(Find-F4keH0undRecyclableObject @groupRecycleParams)
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($recyclableGroups.Count) recyclable group objects."
                }
                catch {
                    Write-Warning "[$($MyInvocation.MyCommand)] - Failed to discover recyclable groups: $($_.Exception.Message)"
                }
            }

            # ------------------------------------------------------------------
            # Phase 2 - Generate Recycling Opportunities
            # ------------------------------------------------------------------
            Write-Verbose "[$($MyInvocation.MyCommand)] - Phase 2: Generating recycling-based opportunities..."

            # Recycling Opportunity: StaleAdminLure from recycled users
            foreach ($recyclableUser in ($recyclableUsers | Where-Object { $_.RecommendedDecoyType -eq 'StaleAdminLure' } | Select-Object -First 5)) {
                $targetGroups = @()
                if ($data.Groups.data) {
                    $matchedGroup = $data.Groups.data |
                        Where-Object {
                            $_.Name -like "*VPN*" -or
                            $_.Name -like "*Remote*" -or
                            $_.Name -like "*Desktop*"
                        } |
                        Select-Object -First 1 -ExpandProperty Name

                    if ($matchedGroup) {
                        $targetGroups = @($matchedGroup -replace '@.*$', '')
                    }
                }

                $opportunityShell = [PSCustomObject]@{ DecoyType = "StaleAdminLure" }
                $lastLogonStr = if ($recyclableUser.LastLogonDate) { $recyclableUser.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
                $opportunity = [PSCustomObject]@{
                    ID               = $opportunityId++
                    Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType        = "StaleAdminLure"
                    Strategy         = "Recycle"
                    RecyclableObject = $recyclableUser.Identity
                    Justification    = "Recycles legitimately old user '$($recyclableUser.SamAccountName)' (RID: $($recyclableUser.RID), created $($recyclableUser.whenCreated.ToString('yyyy-MM-dd')), last logon: $lastLogonStr, staleness: $([math]::Round($recyclableUser.StalenessScore, 1))%) to simulate a dormant privileged account."
                    Template         = @{
                        SamAccountName = $recyclableUser.SamAccountName
                        Name           = $recyclableUser.SamAccountName
                        Description    = "Legacy Administrator Account - $(Get-Random -InputObject @('Finance', 'HR', 'IT', 'Operations', 'Development')) Department"
                        GroupsToAdd    = $targetGroups
                    }
                }
                $allOpportunities.Add($opportunity)
            }

            # Recycling Opportunity: KerberoastableUser from recycled service-like users
            foreach ($recyclableUser in ($recyclableUsers | Where-Object { $_.RecommendedDecoyType -eq 'KerberoastableUser' } | Select-Object -First 3)) {
                $sqlHost = Get-Random -InputObject @('prod-sql', 'app-db', 'reporting-sql', 'warehouse-db')
                $domainPrefix = if ($data.Domains.data -and $data.Domains.data[0].Name) { ($data.Domains.data[0].Name -split '\.')[0] } else { 'corp' }
                $decoySPN = "MSSQLSvc/$sqlHost.$domainPrefix.local:1433"

                $opportunityShell = [PSCustomObject]@{ DecoyType = "KerberoastableUser" }
                $opportunity = [PSCustomObject]@{
                    ID               = $opportunityId++
                    Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType        = "KerberoastableUser"
                    Strategy         = "Recycle"
                    RecyclableObject = $recyclableUser.Identity
                    Justification    = "Recycles legitimately old user '$($recyclableUser.SamAccountName)' (RID: $($recyclableUser.RID), created $($recyclableUser.whenCreated.ToString('yyyy-MM-dd')), staleness: $([math]::Round($recyclableUser.StalenessScore, 1))%) and adds SPN '$decoySPN' to detect Kerberoasting (TTP T1558.003)."
                    Template         = @{
                        SamAccountName       = $recyclableUser.SamAccountName
                        Name                 = $recyclableUser.SamAccountName
                        Description          = "Production SQL Service Account"
                        ServicePrincipalName = $decoySPN
                    }
                }
                $allOpportunities.Add($opportunity)
            }

            # Recycling Opportunity: UnconstrainedDelegationComputer from recycled computers
            foreach ($recyclableComputer in ($recyclableComputers | Select-Object -First 3)) {
                $opportunityShell = [PSCustomObject]@{ DecoyType = "UnconstrainedDelegationComputer" }
                $lastLogonStr = if ($recyclableComputer.LastLogonDate) { $recyclableComputer.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
                $opportunity = [PSCustomObject]@{
                    ID               = $opportunityId++
                    Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType        = "UnconstrainedDelegationComputer"
                    Strategy         = "Recycle"
                    RecyclableObject = $recyclableComputer.Identity
                    Justification    = "Recycles legitimately old computer '$($recyclableComputer.Name)' (RID: $($recyclableComputer.RID), created $($recyclableComputer.whenCreated.ToString('yyyy-MM-dd')), last logon: $lastLogonStr, staleness: $([math]::Round($recyclableComputer.StalenessScore, 1))%) and enables Unconstrained Delegation to lure attackers seeking credential theft targets."
                    Template         = @{
                        Name        = $recyclableComputer.Name
                        Description = "Legacy Development Server for Production Environment"
                    }
                }
                $allOpportunities.Add($opportunity)
            }

            # Recycling Opportunity: DNSAdminUser (if DnsAdmins group exists)
            $dnsAdminsGroupRecycle = $data.Groups.data | Where-Object { $_.Name -like "*DNSADMINS@*" } | Select-Object -First 1
            if ($dnsAdminsGroupRecycle -and $recyclableUsers.Count -gt 0) {
                $dnsRecyclableUser = $recyclableUsers |
                    Where-Object { $_.RecommendedDecoyType -eq 'DNSAdminUser' -or $_.RecommendedDecoyType -eq 'StaleAdminLure' } |
                    Select-Object -First 1

                if ($dnsRecyclableUser) {
                    $opportunityShell = [PSCustomObject]@{ DecoyType = "DNSAdminUser" }
                    $opportunity = [PSCustomObject]@{
                        ID               = $opportunityId++
                        Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                        DecoyType        = "DNSAdminUser"
                        Strategy         = "Recycle"
                        RecyclableObject = $dnsRecyclableUser.Identity
                        Justification    = "Recycles legitimately old user '$($dnsRecyclableUser.SamAccountName)' (RID: $($dnsRecyclableUser.RID), created $($dnsRecyclableUser.whenCreated.ToString('yyyy-MM-dd')), staleness: $([math]::Round($dnsRecyclableUser.StalenessScore, 1))%) and adds to 'DnsAdmins' group to detect DLL loading privilege escalation attempts."
                        Template         = @{
                            SamAccountName = $dnsRecyclableUser.SamAccountName
                            Name           = $dnsRecyclableUser.SamAccountName
                            Description    = "DNS Management Service Account"
                            GroupsToAdd    = @(($dnsAdminsGroupRecycle.Name -split '@')[0])
                        }
                    }
                    $allOpportunities.Add($opportunity)
                }
            }

            # Recycling Opportunity: ACLAttackPath from recycled user + recycled group
            if ($recyclableUsers.Count -gt 0 -and $recyclableGroups.Count -gt 0) {
                $aclRecyclableUser = $recyclableUsers | Select-Object -First 1
                $aclRecyclableGroup = $recyclableGroups | Select-Object -First 1

                $opportunityShell = [PSCustomObject]@{ DecoyType = "ACLAttackPath" }
                $opportunity = [PSCustomObject]@{
                    ID               = $opportunityId++
                    Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType        = "ACLAttackPath"
                    Strategy         = "Recycle"
                    RecyclableObject = @{
                        User  = $aclRecyclableUser.Identity
                        Group = $aclRecyclableGroup.Identity
                    }
                    Justification    = "Creates synthetic ACL attack path using recycled user '$($aclRecyclableUser.SamAccountName)' (RID: $($aclRecyclableUser.RID), created $($aclRecyclableUser.whenCreated.ToString('yyyy-MM-dd'))) granted WriteMembers on recycled group '$($aclRecyclableGroup.Name)' (RID: $($aclRecyclableGroup.RID), created $($aclRecyclableGroup.whenCreated.ToString('yyyy-MM-dd'))). Both objects have authentic aging metadata."
                    Template         = @{
                        DecoyUserSamAccountName = $aclRecyclableUser.SamAccountName
                        DecoyGroupName          = $aclRecyclableGroup.Name
                        Permission              = "WriteMembers"
                    }
                }
                $allOpportunities.Add($opportunity)
            }

            Write-Verbose "[$($MyInvocation.MyCommand)] - Generated $($allOpportunities.Count) recycling opportunities."

            # ------------------------------------------------------------------
            # Phase 3 - Generate Creation Opportunities (only if not RecyclingOnly)
            # ------------------------------------------------------------------
            if (-not $RecyclingOnly) {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Phase 3: Generating creation-based opportunities (fallback)..."

                # --- Analysis Logic - Stale Privileged Admins ---
                Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Stale Privileged Admins..."
                $privilegedGroupBlacklist = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Server Operators", "Backup Operators", "Account Operators", "Print Operators")
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
                        $memberOfNames = ($admin.MemberOf | ForEach-Object {
                            $groupDN = $_
                            ($data.Groups.data | Where-Object { $groupDN -eq $_.ObjectIdentifier }).Name
                        })
                        $safeGroup = $memberOfNames | Where-Object { $privilegedGroupBlacklist -notcontains (($_.split('@'))[0]) } | Select-Object -First 1
                        if ($safeGroup) {
                            $safeGroupsToAdd += ($safeGroup -split '@')[0]
                        }
                    }
                    $opportunityShell = [PSCustomObject]@{ DecoyType = "StaleAdminLure" }
                    $opportunity = [PSCustomObject]@{
                        ID               = $opportunityId++
                        Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                        DecoyType        = $opportunityShell.DecoyType
                        Strategy         = "Create"
                        RecyclableObject = $null
                        Justification    = "Mimics the real dormant Domain Admin '$($admin.Properties.samaccountname)' (password last set $daysSincePwdSet days ago)."
                        Template         = @{
                            Name           = "$($admin.Properties.samaccountname)_backup"
                            Description    = "Legacy Admin Account for $($admin.Properties.samaccountname)"
                            SamAccountName = $admin.Properties.samaccountname
                            GroupsToAdd    = $safeGroupsToAdd
                        }
                    }
                    $allOpportunities.Add($opportunity)
                }

                # --- Analysis Logic - Kerberoastable Lures ---
                Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Kerberoastable Lure opportunities..."
                $kerberoastableTemplateUser = $data.Users.data | Where-Object { $_.Properties.hasspn -eq $true } | Select-Object -First 1
                if ($null -ne $kerberoastableTemplateUser) {
                    $domainName = $kerberoastableTemplateUser.Properties.domain
                    $decoySPN = "MSSQLSvc/decoy-sql-prod-01.$($domainName):1433"
                    $opportunityShell = [PSCustomObject]@{ DecoyType = "KerberoastableUser" }
                    $opportunity = [PSCustomObject]@{
                        ID               = $opportunityId++
                        Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                        DecoyType        = $opportunityShell.DecoyType
                        Strategy         = "Create"
                        RecyclableObject = $null
                        Justification    = "Creates an attractive Kerberoastable user with a common SPN format (e.g., MSSQLSvc) to detect TTP T1558.003."
                        Template         = @{ Name = "svc_mssql_prod"; SamAccountName = "svc_mssql_prod"; Description = "Production SQL Service Account"; ServicePrincipalName = $decoySPN }
                    }
                    $allOpportunities.Add($opportunity)
                }

                # --- Analysis Logic - Unconstrained Delegation ---
                Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Unconstrained Delegation computers..."
                $unconstrainedComputers = $data.Computers.data | Where-Object { $_.Properties.unconstraineddelegation -eq $true }
                foreach ($computer in $unconstrainedComputers) {
                    $opportunityShell = [PSCustomObject]@{ DecoyType = "UnconstrainedDelegationComputer" }
                    $opportunity = [PSCustomObject]@{
                        ID               = $opportunityId++
                        Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                        DecoyType        = $opportunityShell.DecoyType
                        Strategy         = "Create"
                        RecyclableObject = $null
                        Justification    = "Mimics the real server with Unconstrained Delegation '$($computer.Name)' which is a high-value target for credential theft."
                        Template         = @{ Name = ($computer.Properties.name -split '\.')[0] + "_DEV"; Description = "Legacy Dev Server for $($computer.Properties.name)" }
                    }
                    $allOpportunities.Add($opportunity)
                }

                # --- Analysis Logic - DNSAdmins User ---
                Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for DNSAdmins privilege escalation path..."
                $dnsAdminsGroup = $data.Groups.data | Where-Object { $_.Name -like "*DNSADMINS@*" } | Select-Object -First 1
                if ($dnsAdminsGroup) {
                    $opportunityShell = [PSCustomObject]@{ DecoyType = "DNSAdminUser" }
                    $opportunity = [PSCustomObject]@{
                        ID               = $opportunityId++
                        Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                        DecoyType        = $opportunityShell.DecoyType
                        Strategy         = "Create"
                        RecyclableObject = $null
                        Justification    = "Creates a decoy user and adds it to the highly privileged 'DnsAdmins' group to detect attempts at DLL loading on DNS servers."
                        Template         = @{ Name = "svc_dns_manager"; SamAccountName = "svc_dns_manager"; Description = "DNS Management Service Account"; GroupsToAdd = @(($dnsAdminsGroup.Name -split '@')[0]) }
                    }
                    $allOpportunities.Add($opportunity)
                }

                # --- Analysis Logic - Fake ACL Attack Path ---
                Write-Verbose "[$($MyInvocation.MyCommand)] - Analyzing for Fake ACL Attack Path opportunity..."
                $opportunityShell = [PSCustomObject]@{ DecoyType = "ACLAttackPath" }
                $opportunity = [PSCustomObject]@{
                    ID               = $opportunityId++
                    Rank             = Get-F4keH0undRank -Opportunity $opportunityShell
                    DecoyType        = $opportunityShell.DecoyType
                    Strategy         = "Create"
                    RecyclableObject = $null
                    Justification    = "Creates a synthetic ACL attack path where a decoy user is given write access to a decoy group, luring attackers who use BloodHound to find ACL vulnerabilities."
                    Template         = @{ DecoyUserName = "helpdesk_temp"; DecoyGroupName = "Tier2_App_Admins"; Permission = "WriteMembers" }
                }
                $allOpportunities.Add($opportunity)
            }
            else {
                Write-Verbose "[$($MyInvocation.MyCommand)] - Skipping creation-based opportunities (-RecyclingOnly specified)."
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Azure') {
            $data = Get-F4keH0undData -Path $AzureHoundPath -DataType 'Azure' -ErrorAction SilentlyContinue
            # ... (Azure analysis logic is unchanged) ...
        }
    }
    end {
        # Check RecyclingOnly condition - warn if nothing found
        if ($RecyclingOnly -and $allOpportunities.Count -eq 0) {
            Write-Warning "[$($MyInvocation.MyCommand)] - RecyclingOnly specified but no recyclable objects found matching criteria (MinAge: $RecyclingMinimumAgeDays days, MaxAge: $RecyclingMaximumAgeDays days)."
            return @()
        }

        # ------------------------------------------------------------------
        # Phase 4 - Adjust Ranking for Recycling Preference
        # ------------------------------------------------------------------
        if ($PreferRecycling -or (-not $PSBoundParameters.ContainsKey('PreferRecycling') -and ($recyclableUsers.Count -gt 0 -or $recyclableComputers.Count -gt 0 -or $recyclableGroups.Count -gt 0))) {
            foreach ($opp in $allOpportunities) {
                if ($opp.Strategy -eq 'Recycle') {
                    switch ($opp.Rank) {
                        'Low'    { $opp.Rank = 'Medium' }
                        'Medium' { $opp.Rank = 'High' }
                        'High'   { $opp.Rank = 'Critical' }
                    }
                }
            }
            $boostedCount = ($allOpportunities | Where-Object { $_.Strategy -eq 'Recycle' }).Count
            Write-Verbose "[$($MyInvocation.MyCommand)] - Boosted ranking for $boostedCount recycling opportunities."
        }

        Write-Verbose "[$($MyInvocation.MyCommand)] - ======================================="
        Write-Verbose "[$($MyInvocation.MyCommand)] - RECYCLING-AWARE OPPORTUNITY ANALYSIS"
        Write-Verbose "[$($MyInvocation.MyCommand)] - ======================================="
        Write-Verbose "[$($MyInvocation.MyCommand)] - Recyclable users found    : $($recyclableUsers.Count)"
        Write-Verbose "[$($MyInvocation.MyCommand)] - Recyclable computers found: $($recyclableComputers.Count)"
        Write-Verbose "[$($MyInvocation.MyCommand)] - Recyclable groups found   : $($recyclableGroups.Count)"
        $recycleCount = ($allOpportunities | Where-Object { $_.Strategy -eq 'Recycle' }).Count
        $createCount  = ($allOpportunities | Where-Object { $_.Strategy -eq 'Create' }).Count
        Write-Verbose "[$($MyInvocation.MyCommand)] - Total recycling opportunities: $recycleCount"
        Write-Verbose "[$($MyInvocation.MyCommand)] - Total creation opportunities : $createCount"
        Write-Verbose "[$($MyInvocation.MyCommand)] - ======================================="
        Write-Verbose "[$($MyInvocation.MyCommand)] - Analysis complete. Found $($allOpportunities.Count) opportunities."

        $allOpportunities | Sort-Object @{
            Expression = { if ($_.Strategy -eq 'Recycle') { 0 } else { 1 } }
        }, @{
            Expression = { $rankOrder[$_.Rank] }
        }, @{
            Expression = {
                if ($_.RecyclableObject -and
                    $_.RecyclableObject -isnot [hashtable] -and
                    ($_.RecyclableObject.PSObject.Properties.Name -contains 'StalenessScore')) {
                    -$_.RecyclableObject.StalenessScore
                }
                else {
                    0
                }
            }
        }
    }
}
