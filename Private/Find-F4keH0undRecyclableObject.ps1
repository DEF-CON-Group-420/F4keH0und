<#
.SYNOPSIS
    Discovers stale or disabled Active Directory objects suitable for recycling as decoy objects.

.DESCRIPTION
    Find-F4keH0undRecyclableObject scans Active Directory for disabled or stale User, Computer,
    or Group objects that can be repurposed as deception decoys. Recycling existing objects
    preserves their original RID and creation timestamps, avoiding the "RID anomaly" that
    betrays newly created decoys to attackers performing domain enumeration.

    Each discovered object is assigned a Staleness Score (0-100) indicating its suitability
    for recycling, based on object age, inactivity duration, group isolation, and description
    emptiness. Objects are returned sorted by StalenessScore descending.

.PARAMETER Type
    The type of AD object to search for. Accepted values: User, Computer, Group.

.PARAMETER MinimumAgeDays
    Minimum age in days for candidate objects. Objects newer than this threshold are excluded.
    Default: 180 days.

.PARAMETER MaximumAgeDays
    Maximum age in days for candidate objects. Objects older than this threshold are excluded.
    Default: 3650 days (approximately 10 years).

.PARAMETER ExcludeOUs
    An array of DistinguishedName patterns for Organizational Units to exclude from results.
    Supports wildcard matching (e.g., "OU=VIP,DC=contoso,DC=local" or "OU=VIP,*").

.PARAMETER MaxResults
    Maximum number of results to return after sorting by StalenessScore descending. Default: 50.

.PARAMETER Credential
    PSCredential object for authenticating against a remote domain controller.

.PARAMETER Server
    The FQDN or hostname of the target domain controller for cross-domain operations.

.EXAMPLE
    $recyclableUsers = Find-F4keH0undRecyclableObject -Type User -MinimumAgeDays 180 -Server "DC01.contoso.local" -Credential $cred -Verbose

    Finds disabled, stale user accounts older than 180 days on the specified domain controller.

.EXAMPLE
    $recyclableComputers = Find-F4keH0undRecyclableObject -Type Computer -MinimumAgeDays 90 -MaxResults 10

    Finds up to 10 stale or disabled computer objects older than 90 days in the current domain.

.EXAMPLE
    $recyclableGroups = Find-F4keH0undRecyclableObject -Type Group -MinimumAgeDays 365 -ExcludeOUs @("OU=VIP,DC=contoso,DC=local")

    Finds empty, stale security groups older than one year, excluding objects in the VIP OU.

.EXAMPLE
    $recyclableUsers | Select-Object SamAccountName, StalenessScore, DaysSinceCreation, RecommendedDecoyType | Format-Table

    Displays a summary table of discovered recyclable users with their staleness scores and recommended decoy types.
#>
function Find-F4keH0undRecyclableObject {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Computer", "Group")]
        [string]$Type,

        [Parameter()]
        [int]$MinimumAgeDays = 180,

        [Parameter()]
        [int]$MaximumAgeDays = 3650,

        [Parameter()]
        [string[]]$ExcludeOUs,

        [Parameter()]
        [int]$MaxResults = 50,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "[$($MyInvocation.MyCommand)] - The 'ActiveDirectory' module is not installed. Please install RSAT-AD-Tools."
        return @()
    }

    if ($MinimumAgeDays -ge $MaximumAgeDays) {
        Write-Error "[$($MyInvocation.MyCommand)] - MinimumAgeDays ($MinimumAgeDays) must be less than MaximumAgeDays ($MaximumAgeDays)."
        return @()
    }

    $adParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

    $now = Get-Date
    $minimumAgeThreshold = $now.AddDays(-$MinimumAgeDays)
    $maximumAgeThreshold = $now.AddDays(-$MaximumAgeDays)

    $activeDescriptionKeywords = @('service', 'production', 'critical', 'backup')
    $excludedSamPrefixes = @('krbtgt', 'MSOL_', 'AAD_', 'AZUREADSSOACC')
    $privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators')

    Write-Verbose "[$($MyInvocation.MyCommand)] - Starting discovery for Type='$Type', MinAge=$MinimumAgeDays days, MaxAge=$MaximumAgeDays days."

    $rawObjects = @()

    switch ($Type) {
        'User' {
            try {
                $userProperties = @(
                    'SamAccountName', 'Name', 'DistinguishedName', 'Enabled', 'LastLogonDate',
                    'PasswordLastSet', 'whenCreated', 'Description', 'MemberOf', 'SID'
                )

                $queryParams = $adParams.Clone()
                $queryParams['Filter'] = "Enabled -eq '$false'"
                $queryParams['Properties'] = $userProperties

                Write-Verbose "[$($MyInvocation.MyCommand)] - Querying AD for disabled users."
                $candidates = @(Get-ADUser @queryParams)
                Write-Verbose "[$($MyInvocation.MyCommand)] - Initial query returned $($candidates.Count) disabled users."

                $candidates = @($candidates | Where-Object {
                    $_.whenCreated -le $minimumAgeThreshold -and $_.whenCreated -ge $maximumAgeThreshold
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After creation date filter: $($candidates.Count) users remain."

                $candidates = @($candidates | Where-Object {
                    $null -eq $_.PasswordLastSet -or $_.PasswordLastSet -le $minimumAgeThreshold
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After PasswordLastSet filter: $($candidates.Count) users remain."

                $candidates = @($candidates | Where-Object {
                    $desc = $_.Description
                    $isActive = $false
                    foreach ($keyword in $activeDescriptionKeywords) {
                        if ($desc -and $desc -like "*$keyword*") {
                            $isActive = $true
                            break
                        }
                    }
                    -not $isActive
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After description keyword filter: $($candidates.Count) users remain."

                $candidates = @($candidates | Where-Object {
                    $sam = $_.SamAccountName
                    $isExcluded = $false
                    foreach ($prefix in $excludedSamPrefixes) {
                        if ($sam -like "$prefix*") {
                            $isExcluded = $true
                            break
                        }
                    }
                    -not $isExcluded
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After SAM prefix filter: $($candidates.Count) users remain."

                $candidates = @($candidates | Where-Object {
                    $memberOf = $_.MemberOf
                    $isPrivileged = $false
                    foreach ($groupDN in $memberOf) {
                        foreach ($groupName in $privilegedGroupNames) {
                            if ($groupDN -like "*CN=$groupName,*") {
                                $isPrivileged = $true
                                break
                            }
                        }
                        if ($isPrivileged) { break }
                    }
                    -not $isPrivileged
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After privileged group filter: $($candidates.Count) users remain."

                $rawObjects = $candidates
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to query AD for users. Error: $($_.Exception.Message)"
                return @()
            }
        }

        'Computer' {
            try {
                $computerProperties = @(
                    'Name', 'SamAccountName', 'DistinguishedName', 'Enabled', 'LastLogonDate',
                    'whenCreated', 'Description', 'OperatingSystem', 'PrimaryGroupID', 'SID'
                )

                $queryParams = $adParams.Clone()
                $queryParams['Filter'] = '*'
                $queryParams['Properties'] = $computerProperties

                Write-Verbose "[$($MyInvocation.MyCommand)] - Querying AD for computer objects."
                $candidates = @(Get-ADComputer @queryParams)
                Write-Verbose "[$($MyInvocation.MyCommand)] - Initial query returned $($candidates.Count) computers."

                $candidates = @($candidates | Where-Object {
                    $_.Enabled -eq $false -or $null -eq $_.LastLogonDate -or $_.LastLogonDate -le $minimumAgeThreshold
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After disabled/stale logon filter: $($candidates.Count) computers remain."

                $candidates = @($candidates | Where-Object {
                    $_.whenCreated -le $minimumAgeThreshold -and $_.whenCreated -ge $maximumAgeThreshold
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After creation date filter: $($candidates.Count) computers remain."

                $candidates = @($candidates | Where-Object { $_.PrimaryGroupID -ne 516 })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After domain controller exclusion: $($candidates.Count) computers remain."

                $candidates = @($candidates | Where-Object {
                    $null -eq $_.OperatingSystem -or $_.OperatingSystem -notlike '*Server*'
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After server OS filter: $($candidates.Count) computers remain."

                $candidates = @($candidates | Where-Object {
                    $desc = $_.Description
                    $isActive = $false
                    foreach ($keyword in $activeDescriptionKeywords) {
                        if ($desc -and $desc -like "*$keyword*") {
                            $isActive = $true
                            break
                        }
                    }
                    -not $isActive
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After description keyword filter: $($candidates.Count) computers remain."

                $rawObjects = $candidates
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to query AD for computers. Error: $($_.Exception.Message)"
                return @()
            }
        }

        'Group' {
            try {
                $groupProperties = @(
                    'Name', 'SamAccountName', 'DistinguishedName', 'GroupCategory', 'GroupScope',
                    'Member', 'whenCreated', 'Description', 'SID'
                )

                $queryParams = $adParams.Clone()
                $queryParams['Filter'] = "GroupCategory -eq 'Security'"
                $queryParams['Properties'] = $groupProperties

                Write-Verbose "[$($MyInvocation.MyCommand)] - Querying AD for security groups."
                $candidates = @(Get-ADGroup @queryParams)
                Write-Verbose "[$($MyInvocation.MyCommand)] - Initial query returned $($candidates.Count) security groups."

                $candidates = @($candidates | Where-Object { $_.Member.Count -eq 0 })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After empty membership filter: $($candidates.Count) groups remain."

                $candidates = @($candidates | Where-Object {
                    $_.whenCreated -le $minimumAgeThreshold -and $_.whenCreated -ge $maximumAgeThreshold
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After creation date filter: $($candidates.Count) groups remain."

                $candidates = @($candidates | Where-Object {
                    $rid = [int]($_.SID.Value -split '-')[-1]
                    $rid -ge 1000
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After built-in group (RID < 1000) exclusion: $($candidates.Count) groups remain."

                $candidates = @($candidates | Where-Object {
                    $_.GroupScope -eq 'Global' -or $_.GroupScope -eq 'Universal'
                })
                Write-Verbose "[$($MyInvocation.MyCommand)] - After scope filter (Global/Universal only): $($candidates.Count) groups remain."

                $rawObjects = $candidates
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to query AD for groups. Error: $($_.Exception.Message)"
                return @()
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('ExcludeOUs') -and $rawObjects.Count -gt 0) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Applying OU exclusion for $($ExcludeOUs.Count) pattern(s)."
        $rawObjects = @($rawObjects | Where-Object {
            $dn = $_.DistinguishedName
            $isExcluded = $false
            foreach ($ouPattern in $ExcludeOUs) {
                if ($dn -like "*$ouPattern*") {
                    $isExcluded = $true
                    break
                }
            }
            -not $isExcluded
        })
        Write-Verbose "[$($MyInvocation.MyCommand)] - After OU exclusion: $($rawObjects.Count) objects remain."
    }

    if ($rawObjects.Count -eq 0) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - No recyclable objects found matching the specified criteria."
        return @()
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Calculating staleness scores for $($rawObjects.Count) candidate(s)."

    $ageDivisor = $MaximumAgeDays - $MinimumAgeDays

    $results = foreach ($obj in $rawObjects) {
        $daysSinceCreation = ($now - $obj.whenCreated).Days

        $lastLogon = $null
        $daysSinceLastLogon = $null
        if ($Type -ne 'Group') {
            $lastLogon = $obj.LastLogonDate
            if ($null -ne $lastLogon) {
                $daysSinceLastLogon = ($now - $lastLogon).Days
            }
        }

        $ageWeight = [Math]::Min(1.0, [Math]::Max(0.0,
            ($daysSinceCreation - $MinimumAgeDays) / $ageDivisor
        ))

        $inactivityWeight = if ($null -eq $lastLogon) {
            1.0
        }
        else {
            [Math]::Min(1.0, [Math]::Max(0.0,
                ($daysSinceLastLogon - $MinimumAgeDays) / $ageDivisor
            ))
        }

        $isolationWeight = if ($Type -eq 'User') {
            if ($null -eq $obj.MemberOf -or $obj.MemberOf.Count -eq 0) { 1.0 } else { 0.5 }
        }
        elseif ($Type -eq 'Group') {
            if ($null -eq $obj.Member -or $obj.Member.Count -eq 0) { 1.0 } else { 0.5 }
        }
        else {
            0.5
        }

        $descriptorWeight = if ([string]::IsNullOrWhiteSpace($obj.Description)) { 1.0 } else { 0.5 }

        $stalenessScore = [Math]::Round(
            ($ageWeight * 40) + ($inactivityWeight * 30) + ($isolationWeight * 20) + ($descriptorWeight * 10),
            1
        )

        $rid = [int]($obj.SID.Value -split '-')[-1]

        $recommendedDecoyType = switch ($Type) {
            'User' {
                $samLower = $obj.SamAccountName.ToLower()
                if ($samLower -like 'svc_*' -or $samLower -like '*service*') {
                    'KerberoastableUser'
                }
                elseif ($obj.MemberOf -and ($obj.MemberOf | Where-Object { $_ -like '*admin*' })) {
                    'StaleAdminLure'
                }
                elseif (($null -eq $obj.MemberOf -or $obj.MemberOf.Count -eq 0) -and $daysSinceCreation -gt 730) {
                    'DNSAdminUser'
                }
                else {
                    'StaleAdminLure'
                }
            }
            'Computer' { 'UnconstrainedDelegationComputer' }
            'Group' { 'ACLAttackPath' }
        }

        [PSCustomObject]@{
            Type                 = $Type
            Identity             = $obj
            SamAccountName       = $obj.SamAccountName
            DistinguishedName    = $obj.DistinguishedName
            SID                  = $obj.SID.Value
            RID                  = $rid
            whenCreated          = $obj.whenCreated
            LastLogonDate        = $lastLogon
            DaysSinceCreation    = $daysSinceCreation
            DaysSinceLastLogon   = $daysSinceLastLogon
            Description          = $obj.Description
            StalenessScore       = $stalenessScore
            RecommendedDecoyType = $recommendedDecoyType
        }
    }

    $sortedResults = @($results | Sort-Object -Property StalenessScore -Descending | Select-Object -First $MaxResults)

    Write-Verbose "[$($MyInvocation.MyCommand)] - Returning $($sortedResults.Count) candidate(s) sorted by StalenessScore descending."
    return $sortedResults
}
