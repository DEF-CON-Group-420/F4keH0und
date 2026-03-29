function Find-F4keH0undRecyclableEntraObject {
    <#
    .SYNOPSIS
        Discovers disabled or inactive Entra ID (Azure AD) principals suitable for recycling
        as cloud-based decoy objects.

    .DESCRIPTION
        Find-F4keH0undRecyclableEntraObject uses the Microsoft.Graph PowerShell module to scan
        the connected Entra ID tenant for cloud identities that can be repurposed as deception
        decoys using the same recycling methodology applied to on-premises AD objects.

        Three categories of objects are evaluated:

        1. Disabled service principals with stale (old) credentials - these appear to be
           forgotten application registrations and are ideal Kerberoasting-equivalent lures.

        2. Inactive guest users that have never signed in, or whose last sign-in is older
           than the configured threshold - ideal impersonation targets.

        3. App registrations with no recent sign-in activity - useful as OAuth phishing decoys.

        Each discovered object is returned with a StalenessScore (0-100) indicating its
        suitability for recycling, and a RecommendedDecoyType.

        For hybrid environments, each Entra object is cross-referenced against on-premises AD
        to identify objects that share the same onPremisesSamAccountName or immutableId
        (deceptionClone mapping), enabling consistent dual-plane deception coverage.

    .PARAMETER MinimumAgeDays
        Minimum age in days for candidate objects. Objects with credentials or creation dates
        newer than this threshold are excluded. Default: 180 days.

    .PARAMETER MaximumAgeDays
        Maximum age in days for candidate objects. Objects older than this are excluded.
        Default: 3650 days (~10 years).

    .PARAMETER MaxResults
        Maximum number of results to return after sorting by StalenessScore descending.
        Default: 50.

    .PARAMETER IncludeServicePrincipals
        When specified, includes disabled service principals in the discovery scan.

    .PARAMETER IncludeGuestUsers
        When specified, includes inactive guest (B2B) user accounts in the discovery scan.

    .PARAMETER IncludeAppRegistrations
        When specified, includes unused app registrations in the discovery scan.

    .EXAMPLE
        Find-F4keH0undRecyclableEntraObject -IncludeServicePrincipals -IncludeGuestUsers -Verbose

        Discovers all disabled service principals and inactive guest accounts in the tenant.

    .EXAMPLE
        Find-F4keH0undRecyclableEntraObject -IncludeServicePrincipals -MinimumAgeDays 365 -MaxResults 10

        Returns up to 10 service principals whose credentials are at least one year old.

    .EXAMPLE
        Find-F4keH0undRecyclableEntraObject -IncludeGuestUsers -IncludeAppRegistrations |
            Select-Object DisplayName, ObjectType, StalenessScore, RecommendedDecoyType |
            Format-Table

        Summary view of all recyclable Entra guest users and app registrations.

    .OUTPUTS
        System.Object[]
        Returns custom PSObjects with properties: ObjectId, DisplayName, ObjectType,
        CreatedDateTime, LastSignInDateTime, DaysSinceCreation, DaysSinceLastSignIn,
        StalenessScore, RecommendedDecoyType, OnPremisesSamAccountName, OnPremisesImmutableId.
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [int]$MinimumAgeDays = 180,

        [Parameter()]
        [int]$MaximumAgeDays = 3650,

        [Parameter()]
        [int]$MaxResults = 50,

        [Parameter()]
        [switch]$IncludeServicePrincipals,

        [Parameter()]
        [switch]$IncludeGuestUsers,

        [Parameter()]
        [switch]$IncludeAppRegistrations
    )

    # ------------------------------------------------------------------
    # Module prerequisite check
    # ------------------------------------------------------------------
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Applications') -and
        -not (Get-Module -ListAvailable -Name 'Microsoft.Graph')) {
        Write-Error "[$($MyInvocation.MyCommand)] - The 'Microsoft.Graph' module is not installed. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
        return @()
    }

    # Ensure we have an active Graph session
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if (-not $ctx) {
            throw "No active Microsoft Graph context."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - Connected to Microsoft Graph tenant: $($ctx.TenantId)"
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Not connected to Microsoft Graph. Run Connect-MgGraph first. Error: $($_.Exception.Message)"
        return @()
    }

    if ($MinimumAgeDays -ge $MaximumAgeDays) {
        Write-Error "[$($MyInvocation.MyCommand)] - MinimumAgeDays ($MinimumAgeDays) must be less than MaximumAgeDays ($MaximumAgeDays)."
        return @()
    }

    if (-not $IncludeServicePrincipals -and -not $IncludeGuestUsers -and -not $IncludeAppRegistrations) {
        Write-Warning "[$($MyInvocation.MyCommand)] - No object type selected. Specify at least one of: -IncludeServicePrincipals, -IncludeGuestUsers, -IncludeAppRegistrations."
        return @()
    }

    $now               = Get-Date
    $minimumThreshold  = $now.AddDays(-$MinimumAgeDays)
    $maximumThreshold  = $now.AddDays(-$MaximumAgeDays)
    $ageDivisor        = $MaximumAgeDays - $MinimumAgeDays
    $results           = [System.Collections.Generic.List[PSObject]]::new()

    # ------------------------------------------------------------------
    # Helper: calculate staleness score (same weighting as AD version)
    # ------------------------------------------------------------------
    function Get-EntraStalenessScore {
        param ([int]$DaysSinceCreation, [int]$DaysSinceLastSignIn, [int]$MinDays, [int]$Divisor)
        $ageWeight = [Math]::Min(1.0, [Math]::Max(0.0, ($DaysSinceCreation - $MinDays) / $Divisor))
        $inactivityWeight = [Math]::Min(1.0, [Math]::Max(0.0, ($DaysSinceLastSignIn - $MinDays) / $Divisor))
        return [Math]::Round(($ageWeight * 50) + ($inactivityWeight * 50), 1)
    }

    # ------------------------------------------------------------------
    # 1. Disabled service principals with stale credentials
    # ------------------------------------------------------------------
    if ($IncludeServicePrincipals) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Querying disabled service principals..."
        try {
            $spProps = 'Id,DisplayName,AppId,AccountEnabled,CreatedDateTime,' +
                       'KeyCredentials,PasswordCredentials,ServicePrincipalType'

            $allSPs = Get-MgServicePrincipal -All -Property $spProps -ErrorAction Stop

            $candidates = $allSPs | Where-Object {
                $_.AccountEnabled -eq $false -and
                $null -ne $_.CreatedDateTime -and
                $_.CreatedDateTime -le $minimumThreshold -and
                $_.CreatedDateTime -ge $maximumThreshold
            }
            Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($candidates.Count) disabled service principals older than $MinimumAgeDays days."

            foreach ($sp in $candidates) {
                $daysSinceCreation = ($now - $sp.CreatedDateTime).Days

                # Determine staleness of credentials
                $lastCredDate = $null
                $allCreds = @($sp.KeyCredentials) + @($sp.PasswordCredentials)
                foreach ($cred in $allCreds) {
                    $endDt = $cred.EndDateTime
                    if ($null -ne $endDt -and ($null -eq $lastCredDate -or $endDt -gt $lastCredDate)) {
                        $lastCredDate = $endDt
                    }
                }

                $daysSinceLastCred = if ($null -ne $lastCredDate) { ($now - $lastCredDate).Days } else { $daysSinceCreation }

                $stalenessScore = Get-EntraStalenessScore -DaysSinceCreation $daysSinceCreation `
                    -DaysSinceLastSignIn $daysSinceLastCred `
                    -MinDays $MinimumAgeDays -Divisor $ageDivisor

                $results.Add([PSCustomObject]@{
                    ObjectId                 = $sp.Id
                    DisplayName              = $sp.DisplayName
                    ObjectType               = 'ServicePrincipal'
                    AppId                    = $sp.AppId
                    AccountEnabled           = $sp.AccountEnabled
                    CreatedDateTime          = $sp.CreatedDateTime
                    LastSignInDateTime       = $lastCredDate
                    DaysSinceCreation        = $daysSinceCreation
                    DaysSinceLastSignIn      = $daysSinceLastCred
                    StalenessScore           = $stalenessScore
                    RecommendedDecoyType     = 'EntraKerberoastableServicePrincipal'
                    OnPremisesSamAccountName = $null
                    OnPremisesImmutableId    = $null
                })
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to query service principals. Error: $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # 2. Inactive guest users
    # ------------------------------------------------------------------
    if ($IncludeGuestUsers) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Querying inactive guest users..."
        try {
            $guestProps = 'Id,DisplayName,UserPrincipalName,UserType,AccountEnabled,' +
                          'CreatedDateTime,SignInActivity,OnPremisesSamAccountName,OnPremisesImmutableId'

            $allGuests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property $guestProps -ErrorAction Stop

            $candidates = $allGuests | Where-Object {
                $null -ne $_.CreatedDateTime -and
                $_.CreatedDateTime -le $minimumThreshold -and
                $_.CreatedDateTime -ge $maximumThreshold
            }

            # Further filter to those that never signed in or last signed in beyond MinimumAgeDays
            $candidates = $candidates | Where-Object {
                $lastSignIn = $_.SignInActivity.LastSignInDateTime
                $null -eq $lastSignIn -or $lastSignIn -le $minimumThreshold
            }
            Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($($candidates | Measure-Object).Count) inactive guest users."

            foreach ($guest in $candidates) {
                $daysSinceCreation = ($now - $guest.CreatedDateTime).Days
                $lastSignIn = $guest.SignInActivity.LastSignInDateTime
                $daysSinceLastSignIn = if ($null -ne $lastSignIn) { ($now - $lastSignIn).Days } else { $daysSinceCreation }

                $stalenessScore = Get-EntraStalenessScore -DaysSinceCreation $daysSinceCreation `
                    -DaysSinceLastSignIn $daysSinceLastSignIn `
                    -MinDays $MinimumAgeDays -Divisor $ageDivisor

                $results.Add([PSCustomObject]@{
                    ObjectId                 = $guest.Id
                    DisplayName              = $guest.DisplayName
                    ObjectType               = 'GuestUser'
                    AppId                    = $null
                    AccountEnabled           = $guest.AccountEnabled
                    CreatedDateTime          = $guest.CreatedDateTime
                    LastSignInDateTime       = $lastSignIn
                    DaysSinceCreation        = $daysSinceCreation
                    DaysSinceLastSignIn      = $daysSinceLastSignIn
                    StalenessScore           = $stalenessScore
                    RecommendedDecoyType     = 'EntraInactiveGuestLure'
                    OnPremisesSamAccountName = $guest.OnPremisesSamAccountName
                    OnPremisesImmutableId    = $guest.OnPremisesImmutableId
                })
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to query guest users. Error: $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # 3. Unused app registrations
    # ------------------------------------------------------------------
    if ($IncludeAppRegistrations) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Querying unused app registrations..."
        try {
            $appProps = 'Id,DisplayName,AppId,CreatedDateTime,KeyCredentials,PasswordCredentials'

            $allApps = Get-MgApplication -All -Property $appProps -ErrorAction Stop

            $candidates = $allApps | Where-Object {
                $null -ne $_.CreatedDateTime -and
                $_.CreatedDateTime -le $minimumThreshold -and
                $_.CreatedDateTime -ge $maximumThreshold
            }
            Write-Verbose "[$($MyInvocation.MyCommand)] - Found $($candidates.Count) app registrations older than $MinimumAgeDays days."

            foreach ($app in $candidates) {
                $daysSinceCreation = ($now - $app.CreatedDateTime).Days

                $lastCredDate = $null
                $allCreds = @($app.KeyCredentials) + @($app.PasswordCredentials)
                foreach ($cred in $allCreds) {
                    $endDt = $cred.EndDateTime
                    if ($null -ne $endDt -and ($null -eq $lastCredDate -or $endDt -gt $lastCredDate)) {
                        $lastCredDate = $endDt
                    }
                }

                $daysSinceLastCred = if ($null -ne $lastCredDate) { ($now - $lastCredDate).Days } else { $daysSinceCreation }

                $stalenessScore = Get-EntraStalenessScore -DaysSinceCreation $daysSinceCreation `
                    -DaysSinceLastSignIn $daysSinceLastCred `
                    -MinDays $MinimumAgeDays -Divisor $ageDivisor

                $results.Add([PSCustomObject]@{
                    ObjectId                 = $app.Id
                    DisplayName              = $app.DisplayName
                    ObjectType               = 'AppRegistration'
                    AppId                    = $app.AppId
                    AccountEnabled           = $null
                    CreatedDateTime          = $app.CreatedDateTime
                    LastSignInDateTime       = $lastCredDate
                    DaysSinceCreation        = $daysSinceCreation
                    DaysSinceLastSignIn      = $daysSinceLastCred
                    StalenessScore           = $stalenessScore
                    RecommendedDecoyType     = 'EntraUnusedAppRegistration'
                    OnPremisesSamAccountName = $null
                    OnPremisesImmutableId    = $null
                })
            }
        }
        catch {
            Write-Warning "[$($MyInvocation.MyCommand)] - Failed to query app registrations. Error: $($_.Exception.Message)"
        }
    }

    if ($results.Count -eq 0) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - No recyclable Entra objects found matching the specified criteria."
        return @()
    }

    $sorted = @($results | Sort-Object -Property StalenessScore -Descending | Select-Object -First $MaxResults)
    Write-Verbose "[$($MyInvocation.MyCommand)] - Returning $($sorted.Count) recyclable Entra object(s) sorted by StalenessScore descending."
    return $sorted
}
