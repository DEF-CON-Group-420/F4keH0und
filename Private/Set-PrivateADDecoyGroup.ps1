function Set-PrivateADDecoyGroup {
    <#
    .SYNOPSIS
        Recycles an existing empty AD security group by transforming it into a decoy for ACL attack paths.

    .DESCRIPTION
        This function modifies an existing empty Active Directory security group to serve as a decoy target
        in synthetic ACL-based attack paths, preserving its original RID and creation timestamp to avoid
        RID anomaly detection by attackers.

        The function performs extensive safety checks before modification to ensure only appropriate
        groups are recycled (empty, non-privileged, old, non-built-in security groups).

        Primary use case: Creating the target group in a "Fake ACL Attack Path" where a decoy user
        is granted dangerous permissions (e.g., WriteMembers) on this group. When discovered by BloodHound,
        it appears to be a legacy misconfiguration.

        Critical attributes preserved:
        - whenCreated    (maintains authentic aging)
        - objectSID      (preserves original RID)
        - objectGUID     (unique identifier)
        - Name           (keeps original group name)
        - SamAccountName (keeps original identity)
        - DistinguishedName (keeps original location)
        - GroupCategory  (remains Security)
        - GroupScope     (remains Global or Universal)
        - Members        (remains empty)

        Modified attributes:
        - Description (set to decoy description)
        - ManagedBy   (optional, creates additional attack path edges in BloodHound)

    .PARAMETER ExistingGroup
        The ADGroup object to recycle. Typically obtained from Find-F4keH0undRecyclableObject.
        Must be an empty Security group older than 180 days with RID >= 1000.

    .PARAMETER Description
        The new description to apply to the recycled group. Should match the decoy template
        (e.g., "Application Administrators for Tier2").

    .PARAMETER ManagedBy
        Optional. Distinguished Name or SamAccountName of a user/group to set as the manager.
        In BloodHound, this creates a GenericAll edge from the manager to the group,
        adding complexity to the synthetic attack path.

    .PARAMETER Credential
        Credentials for cross-domain operations.

    .PARAMETER Server
        Domain controller to target for the operation.

    .EXAMPLE
        $staleGroup = Find-F4keH0undRecyclableObject -Type Group | Select-Object -First 1
        Set-PrivateADDecoyGroup -ExistingGroup $staleGroup.Identity -Description "Tier 2 Application Admins" -Verbose

    .EXAMPLE
        # Recycle old empty group for ACL attack path with manager
        $oldGroup = Get-ADGroup "Legacy-App-Team" -Properties whenCreated, Members
        Set-PrivateADDecoyGroup -ExistingGroup $oldGroup -Description "Production App Administrators" -ManagedBy "decoy_helpdesk" -WhatIf

    .EXAMPLE
        # Cross-domain group recycling
        $staleGroup = Find-F4keH0undRecyclableObject -Type Group -Server "DC01.contoso.local" -Credential $cred | Select-Object -First 1
        Set-PrivateADDecoyGroup -ExistingGroup $staleGroup.Identity -Description "Legacy VPN Access Group" -Server "DC01.contoso.local" -Credential $cred

    .EXAMPLE
        # Use in ACL attack path scenario (combined with Set-PrivateADACL)
        $decoyGroup = Set-PrivateADDecoyGroup -ExistingGroup $staleGroup -Description "Tier2 Admins"
        # Later: Grant a decoy user WriteMembers permission on this group
        Set-PrivateADACL -TargetObject $decoyGroup -Principal $decoyUser -Permission "WriteMembers"

    .NOTES
        This function replaces New-PrivateADDecoyGroup for recycling-based decoy deployment.
        It will refuse to modify:
        - Non-Security groups (Distribution groups)
        - Groups with members (non-empty)
        - Built-in groups (RID < 1000)
        - Protected groups (Domain Admins, DnsAdmins, etc.)
        - Groups matching protected patterns (Admin*, Exchange*, etc.)
        - Groups younger than 180 days
        - Groups in protected OUs (Builtin, Domain Controllers)

        Empty groups are ideal for recycling because:
        - No risk of disrupting existing access
        - Can be freely granted dangerous ACL permissions for decoy purposes
        - When used in synthetic attack paths, appear to be forgotten legacy groups

        The ManagedBy attribute creates a GenericAll relationship in BloodHound, which can be
        used to create multi-hop attack paths: User -> ManagedBy -> Group -> WriteMembers -> Another Group
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$ExistingGroup,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter()]
        [string]$ManagedBy,

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
    # Refresh the group object with the properties we need for validation
    # ------------------------------------------------------------------
    $getParams = @{
        Identity    = $ExistingGroup
        Properties  = 'whenCreated', 'Members', 'ManagedBy', 'GroupScope',
                      'GroupCategory', 'SID', 'Description', 'DistinguishedName',
                      'Name', 'SamAccountName'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Server'))     { $getParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $getParams['Credential'] = $Credential }

    try {
        $group = Get-ADGroup @getParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to retrieve group '$($ExistingGroup.Name)'. Error: $($_.Exception.Message)"
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Validating group '$($group.Name)'..."

    # ------------------------------------------------------------------
    # Safety Check 1: Must be a Security group
    # ------------------------------------------------------------------
    if ($group.GroupCategory -ne 'Security') {
        throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is not a Security group (GroupCategory: $($group.GroupCategory)). Only Security groups can be recycled as decoys."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 1 PASSED: Group is a Security group (Category: $($group.GroupCategory))."

    # ------------------------------------------------------------------
    # Safety Check 2: Group must be empty
    # ------------------------------------------------------------------
    $memberParams = @{
        Identity    = $group
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Server'))     { $memberParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $memberParams['Credential'] = $Credential }

    try {
        $members = Get-ADGroupMember @memberParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to retrieve members of group '$($group.Name)'. Error: $($_.Exception.Message)"
    }

    if ($members.Count -gt 0) {
        throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' has $($members.Count) member(s). Only empty groups can be recycled."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 2 PASSED: Group is empty (0 members)."

    # ------------------------------------------------------------------
    # Safety Check 3: RID must be >= 1000 (reject built-in groups)
    # ------------------------------------------------------------------
    try {
        $rid = [int]($group.SID.Value.Split('-')[-1])
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to parse RID from SID '$($group.SID.Value)' for group '$($group.Name)'. Error: $($_.Exception.Message)"
    }
    if ($rid -lt 1000) {
        throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is a built-in group (RID: $rid < 1000). Refusing to modify."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 3 PASSED: Not a built-in group (RID: $rid >= 1000)."

    # ------------------------------------------------------------------
    # Safety Check 4: Not in the protected built-in groups list
    # ------------------------------------------------------------------
    $protectedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Server Operators', 'Print Operators', 'Domain Controllers',
        'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers',
        'Group Policy Creator Owners', 'DnsAdmins', 'DnsUpdateProxy',
        'Cert Publishers', 'Domain Computers', 'Domain Users', 'Domain Guests',
        'Protected Users', 'Key Admins', 'Enterprise Key Admins',
        'Cloneable Domain Controllers', 'RAS and IAS Servers',
        'Allowed RODC Password Replication Group', 'Denied RODC Password Replication Group'
    )

    if ($protectedGroups -contains $group.Name) {
        throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is a protected built-in group. Refusing to modify."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 4 PASSED: Not in the protected built-in groups list."

    # ------------------------------------------------------------------
    # Safety Check 5: Not matching protected naming patterns
    # ------------------------------------------------------------------
    $protectedPatterns = @(
        '^Admin',       # Any group starting with "Admin"
        '^Exchange',    # Exchange-related groups
        '^SQL',         # SQL Server groups
        '^DB',          # Database groups
        '^VPN.*Admin',  # VPN admin groups
        '^.*Admins$',   # Groups ending with "Admins"
        '^MSOL_',       # Microsoft Online groups
        '^AAD_',        # Azure AD sync groups
        '^AWS-'         # AWS federation groups
    )

    foreach ($pattern in $protectedPatterns) {
        if ($group.Name -match $pattern) {
            throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' matches protected pattern '$pattern'. Refusing to modify."
        }
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 5 PASSED: Group name does not match any protected patterns."

    # ------------------------------------------------------------------
    # Safety Check 6: Group must be at least 180 days old
    # ------------------------------------------------------------------
    $groupAge = (Get-Date) - $group.whenCreated
    if ($groupAge.TotalDays -lt 180) {
        throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is only $([math]::Round($groupAge.TotalDays)) days old. Minimum 180 days required for safe recycling."
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 6 PASSED: Group age is $([math]::Round($groupAge.TotalDays)) days (minimum 180 required)."

    # ------------------------------------------------------------------
    # Safety Check 7: GroupScope (warn on DomainLocal, don't block)
    # ------------------------------------------------------------------
    if ($group.GroupScope -eq 'DomainLocal') {
        Write-Warning "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is DomainLocal scope. This may limit cross-domain attack path visibility in BloodHound."
    }
    else {
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 7 PASSED: Group scope is $($group.GroupScope) (Global or Universal)."
    }

    # ------------------------------------------------------------------
    # Safety Check 8: Not in a protected OU
    # ------------------------------------------------------------------
    $criticalOUs = @('CN=Builtin,', 'OU=Domain Controllers,')
    foreach ($ou in $criticalOUs) {
        if ($group.DistinguishedName -like "*$ou*") {
            throw "[$($MyInvocation.MyCommand)] - Group '$($group.Name)' is in a protected OU ($ou). Refusing to modify."
        }
    }
    Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 8 PASSED: Group is not in a protected OU."

    # ------------------------------------------------------------------
    # Log original state before any modification
    # ------------------------------------------------------------------
    Write-Verbose "[$($MyInvocation.MyCommand)] - All safety checks passed. Original state:"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Name              : $($group.Name)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   SamAccountName    : $($group.SamAccountName)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   DistinguishedName : $($group.DistinguishedName)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Original RID      : $rid"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Created           : $($group.whenCreated)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   GroupScope        : $($group.GroupScope)"
    Write-Verbose "[$($MyInvocation.MyCommand)] -   Description       : $($group.Description)"

    # ------------------------------------------------------------------
    # ShouldProcess guard
    # ------------------------------------------------------------------
    $actionDescription = "Transform into decoy group with description '$Description'"
    if ($PSBoundParameters.ContainsKey('ManagedBy')) {
        $actionDescription += " and set ManagedBy to '$ManagedBy'"
    }

    if (-not $PSCmdlet.ShouldProcess($group.DistinguishedName, $actionDescription)) {
        return
    }

    # ------------------------------------------------------------------
    # Build Set-ADGroup parameter hashtable
    # ------------------------------------------------------------------
    $setParams = @{
        Identity    = $group
        Description = $Description
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Server'))     { $setParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $setParams['Credential'] = $Credential }

    if ($PSBoundParameters.ContainsKey('ManagedBy')) {
        $setParams['ManagedBy'] = $ManagedBy
        Write-Verbose "[$($MyInvocation.MyCommand)] - Setting ManagedBy to '$ManagedBy' (creates GenericAll edge in BloodHound)."
    }

    # ------------------------------------------------------------------
    # Apply modifications
    # ------------------------------------------------------------------
    Write-Verbose "[$($MyInvocation.MyCommand)] - Modifying description to: '$Description'."

    try {
        Set-ADGroup @setParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Failed to modify group '$($group.Name)'. Error: $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------
    # Retrieve and return the updated object
    # ------------------------------------------------------------------
    $getFinalParams = @{
        Identity    = $group
        Properties  = 'whenCreated', 'Description', 'Members', 'ManagedBy',
                      'GroupScope', 'GroupCategory', 'SID', 'SamAccountName',
                      'DistinguishedName'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Server'))     { $getFinalParams['Server']     = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $getFinalParams['Credential'] = $Credential }

    try {
        $updatedGroup = Get-ADGroup @getFinalParams
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Modifications applied but failed to retrieve updated object. Error: $($_.Exception.Message)"
    }

    $finalRid = try { $updatedGroup.SID.Value.Split('-')[-1] } catch { 'unknown' }
    Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully recycled group '$($updatedGroup.Name)' (RID: $finalRid) created on $($updatedGroup.whenCreated)."
    Write-Verbose "[$($MyInvocation.MyCommand)] - Group remains empty ($(@($updatedGroup.Members).Count) members) and is ready for ACL attack path configuration."

    return $updatedGroup
}
