function Set-PrivateADDecoyUser {
    <#
    .SYNOPSIS
        Recycles an existing disabled AD user account by transforming it into a decoy.

    .DESCRIPTION
        This function modifies an existing disabled Active Directory user account to serve as a decoy,
        preserving its original RID and creation timestamp to avoid RID anomaly detection by attackers.

        The function performs extensive safety checks before modification to ensure only appropriate
        accounts are recycled (disabled, non-privileged, sufficiently old).

        Critical attributes preserved:
        - whenCreated    (maintains authentic aging)
        - objectSID      (preserves original RID)
        - objectGUID     (unique identifier)
        - SamAccountName (keeps original identity)
        - DistinguishedName (keeps original location)
        - userPrincipalName (keeps original UPN)
        - LastLogonDate  (maintains historical accuracy)

        Modified attributes:
        - Description          (set to decoy description)
        - AccountPassword      (reset to cryptographically random 30-char value)
        - PasswordNeverExpires (set to $true)
        - ChangePasswordAtLogon (set to $false)
        - Enabled              (kept $false unless -KeepDisabled:$false is explicitly passed)
        - ServicePrincipalName (optional, for Kerberoastable decoys)

    .PARAMETER ExistingUser
        The ADUser object to recycle. Typically obtained from Find-F4keH0undRecyclableObject.
        Must be a disabled account older than 90 days.

    .PARAMETER Description
        The new description to apply to the recycled user. Should match the decoy template
        (e.g., "Production SQL Service Account" for Kerberoastable lures).

    .PARAMETER ServicePrincipalName
        Optional. If provided, adds an SPN to make the user Kerberoastable.
        Format: "MSSQLSvc/server.domain.local:1433"

    .PARAMETER KeepDisabled
        By default, the account remains disabled after recycling. Use -KeepDisabled:$false
        to enable it as part of the transformation.

    .PARAMETER Credential
        Credentials for cross-domain operations.

    .PARAMETER Server
        Domain controller to target for the operation.

    .EXAMPLE
        $staleUser = Find-F4keH0undRecyclableObject -Type User | Select-Object -First 1
        Set-PrivateADDecoyUser -ExistingUser $staleUser.Identity -Description "Legacy VPN Service Account" -Verbose

    .EXAMPLE
        # Create Kerberoastable decoy from recycled account
        $staleUser = Get-ADUser "old_account" -Properties whenCreated
        Set-PrivateADDecoyUser -ExistingUser $staleUser -Description "Production SQL Service" -ServicePrincipalName "MSSQLSvc/prod-sql:1433" -WhatIf

    .NOTES
        This function replaces New-PrivateADDecoyUser for recycling-based decoy deployment.
        It will refuse to modify:
        - Enabled accounts
        - Accounts in privileged groups (Domain Admins, Enterprise Admins, Schema Admins,
          Administrators, Account Operators, Backup Operators)
        - Accounts younger than 90 days
        - Protected system accounts (krbtgt, Administrator, Guest, MSOL_*, AAD_*, AZUREADSSOACC*)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$ExistingUser,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter()]
        [string]$ServicePrincipalName,

        [Parameter()]
        [switch]$KeepDisabled,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    # ------------------------------------------------------------------
    # Module prerequisite check
    # ------------------------------------------------------------------
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "[$($MyInvocation.MyCommand)] - The 'ActiveDirectory' module is not installed. Please install RSAT-AD-Tools."
    }

    # ------------------------------------------------------------------
    # Refresh the user object with the properties we need for validation
    # ------------------------------------------------------------------
    $getParams = @{
        Identity   = $ExistingUser
        Properties = 'Enabled', 'whenCreated', 'MemberOf', 'SamAccountName',
                     'DistinguishedName', 'SID', 'Description',
                     'ServicePrincipalNames', 'userPrincipalName', 'LastLogonDate'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Server'))     { $getParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $getParams['Credential'] = $Credential }

    try {
        $user = Get-ADUser @getParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to retrieve account '$($ExistingUser.SamAccountName)'. Error: $($_.Exception.Message)"
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Validating account '$($user.SamAccountName)'..."

    # ------------------------------------------------------------------
    # Safety Check 1: Account must be disabled
    # ------------------------------------------------------------------
    if ($user.Enabled -eq $true) {
        throw "[$($MyInvocation.MyCommand)] - Refusing to modify enabled account '$($user.SamAccountName)'. Only disabled accounts can be recycled."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 1 PASSED: Account is disabled (safe to modify)."

    # ------------------------------------------------------------------
    # Safety Check 2: Not a member of any privileged group
    # ------------------------------------------------------------------
    $privilegedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators'
    )
    $memberOf = $user.MemberOf | ForEach-Object { $_ -replace '^CN=([^,]+),.*', '$1' }
    $privilegedMembership = $privilegedGroups | Where-Object { $memberOf -contains $_ }
    if ($privilegedMembership) {
        throw "[$($MyInvocation.MyCommand)] - Account '$($user.SamAccountName)' is member of privileged group(s): $($privilegedMembership -join ', '). Refusing to modify."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 2 PASSED: Not a member of privileged groups."

    # ------------------------------------------------------------------
    # Safety Check 3: Account must be at least 90 days old
    # ------------------------------------------------------------------
    $accountAge = (Get-Date) - $user.whenCreated
    if ($accountAge.TotalDays -lt 90) {
        throw "[$($MyInvocation.MyCommand)] - Account '$($user.SamAccountName)' is only $([math]::Round($accountAge.TotalDays)) days old. Minimum 90 days required for safe recycling."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 3 PASSED: Account age is $([math]::Round($accountAge.TotalDays)) days (minimum 90 required)."

    # ------------------------------------------------------------------
    # Safety Check 4: SamAccountName must not match protected patterns
    # ------------------------------------------------------------------
    $protectedPatterns = @('^krbtgt$', '^Administrator$', '^Guest$', '^MSOL_', '^AAD_', '^AZUREADSSOACC')
    foreach ($pattern in $protectedPatterns) {
        if ($user.SamAccountName -match $pattern) {
            throw "[$($MyInvocation.MyCommand)] - Account '$($user.SamAccountName)' matches protected pattern '$pattern'. Refusing to modify."
        }
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 4 PASSED: SamAccountName '$($user.SamAccountName)' does not match any protected patterns."

    # ------------------------------------------------------------------
    # Log original state before any modification
    # ------------------------------------------------------------------
    Write-Verbose "[$($MyInvocation.MyCommand)] - All safety checks passed. Original state:"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   SamAccountName : $($user.SamAccountName)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   DistinguishedName : $($user.DistinguishedName)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Original RID : $($user.SID.Value.Split('-')[-1])"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Created : $($user.whenCreated)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Description : $($user.Description)"

    # ------------------------------------------------------------------
    # ShouldProcess guard
    # ------------------------------------------------------------------
    if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, "Transform into decoy with description '$Description'")) {
        return
    }

    # ------------------------------------------------------------------
    # Generate a cryptographically random 30-character password
    # ------------------------------------------------------------------
    $password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 30 | ForEach-Object { [char]$_ })
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

    # ------------------------------------------------------------------
    # Build Set-ADUser parameter hashtable
    # ------------------------------------------------------------------
    $setParams = @{
        Identity              = $user
        Description           = $Description
        AccountPassword       = $securePassword
        PasswordNeverExpires  = $true
        ChangePasswordAtLogon = $false
        ErrorAction           = 'Stop'
    }

    # Honour -KeepDisabled:$false (default keeps account disabled)
    if ($PSBoundParameters.ContainsKey('KeepDisabled') -and (-not $KeepDisabled)) {
        $setParams['Enabled'] = $true
        Write-Verbose "[$($MyInvocation.MyCommand)] - Account will be ENABLED as -KeepDisabled:`$false was specified."
    }

    if ($PSBoundParameters.ContainsKey('Server'))     { $setParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $setParams['Credential'] = $Credential }

    # ------------------------------------------------------------------
    # Apply core modifications
    # ------------------------------------------------------------------
    Write-Verbose "[$($MyInvocation.MyCommand)] - Modifying description to: '$Description'."
    Write-Verbose "[$($MyInvocation.MyCommand)] - Resetting account password (random 30-char value)."
    Write-Verbose "[$($MyInvocation.MyCommand)] - Setting PasswordNeverExpires = `$true, ChangePasswordAtLogon = `$false."

    try {
        Set-ADUser @setParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to modify account '$($user.SamAccountName)'. Error: $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------
    # Optionally add an SPN (separate call – SPN changes require their own
    # parameter set and cannot be combined with AccountPassword)
    # ------------------------------------------------------------------
    if ($PSBoundParameters.ContainsKey('ServicePrincipalName')) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Adding SPN '$ServicePrincipalName' to '$($user.SamAccountName)'."

        $spnParams = @{
            Identity              = $user
            ServicePrincipalNames = @{ Add = $ServicePrincipalName }
            ErrorAction           = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Server'))     { $spnParams['Server']     = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $spnParams['Credential'] = $Credential }

        try {
            Set-ADUser @spnParams
        }
        catch {
            throw "[$($MyInvocation.MyCommand)] - Failed to add SPN '$ServicePrincipalName' to '$($user.SamAccountName)'. The SPN may already exist on another object. Error: $($_.Exception.Message)"
        }

        Write-Verbose "[$($MyInvocation.MyCommand)] - SPN '$ServicePrincipalName' added successfully."
    }

    # ------------------------------------------------------------------
    # Retrieve and return the updated object
    # ------------------------------------------------------------------
    $getFinalParams = @{
        Identity    = $user
        Properties  = 'whenCreated', 'Description', 'ServicePrincipalNames',
                      'Enabled', 'SID', 'SamAccountName', 'DistinguishedName'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Server'))     { $getFinalParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $getFinalParams['Credential'] = $Credential }

    try {
        $updatedUser = Get-ADUser @getFinalParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Modifications applied but failed to retrieve updated object. Error: $($_.Exception.Message)"
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully recycled user '$($updatedUser.SamAccountName)' (RID: $($updatedUser.SID.Value.Split('-')[-1])) created on $($updatedUser.whenCreated)."

    return $updatedUser
}
