function Set-PrivateADDecoyComputer {
    <#
    .SYNOPSIS
        Recycles an existing disabled/inactive AD computer account by transforming it into a decoy.

    .DESCRIPTION
        This function modifies an existing disabled or inactive Active Directory computer account
        to serve as a decoy, preserving its original RID and creation timestamp to avoid RID
        anomaly detection by attackers.

        The function performs extensive safety checks before modification to ensure only appropriate
        computers are recycled (inactive, non-DC, sufficiently old, not critical infrastructure).

        Primary use case: Creating Unconstrained Delegation computer decoys that appear to be
        forgotten legacy servers, luring attackers attempting credential theft via delegation abuse.

        Critical attributes preserved:
        - whenCreated      (maintains authentic aging)
        - objectSID        (preserves original RID)
        - objectGUID       (unique identifier)
        - Name             (keeps original computer name)
        - SamAccountName   (keeps original, typically Name + "$")
        - DistinguishedName (keeps original location)
        - DNSHostName      (keeps original DNS name)
        - LastLogonDate    (maintains historical accuracy)
        - OperatingSystem  (maintains authentic OS fingerprint)

        Modified attributes:
        - Description          (set to decoy description)
        - TrustedForDelegation (optional, enables Unconstrained Delegation)
        - Enabled              (kept $false unless -KeepDisabled:$false is explicitly passed)

    .PARAMETER ExistingComputer
        The ADComputer object to recycle. Typically obtained from Find-F4keH0undRecyclableObject.
        Must be a disabled or inactive computer older than 90 days.

    .PARAMETER Description
        The new description to apply to the recycled computer. Should match the decoy template
        (e.g., "Legacy Dev Server for PROD-SQL01").

    .PARAMETER EnableUnconstrainedDelegation
        If specified, enables Unconstrained Delegation (TrustedForDelegation = True) on the
        computer. This makes the decoy attractive to attackers as a credential theft target.

    .PARAMETER KeepDisabled
        By default, the computer remains disabled. Use -KeepDisabled:$false to enable it
        (rarely needed).

    .PARAMETER Credential
        Credentials for cross-domain operations.

    .PARAMETER Server
        Domain controller to target for the operation.

    .EXAMPLE
        $staleComputer = Find-F4keH0undRecyclableObject -Type Computer | Select-Object -First 1
        Set-PrivateADDecoyComputer -ExistingComputer $staleComputer.Identity -Description "Legacy Dev Server" -EnableUnconstrainedDelegation -Verbose

    .EXAMPLE
        # Recycle old workstation as Unconstrained Delegation decoy
        $oldWorkstation = Get-ADComputer "OLD-WS-147" -Properties whenCreated, LastLogonDate
        Set-PrivateADDecoyComputer -ExistingComputer $oldWorkstation -Description "Legacy Test Server for SQL Cluster" -EnableUnconstrainedDelegation -WhatIf

    .EXAMPLE
        # Cross-domain recycling
        $staleComputer = Find-F4keH0undRecyclableObject -Type Computer -Server "DC01.contoso.local" -Credential $cred | Select-Object -First 1
        Set-PrivateADDecoyComputer -ExistingComputer $staleComputer.Identity -Description "Abandoned Dev Server" -EnableUnconstrainedDelegation -Server "DC01.contoso.local" -Credential $cred

    .NOTES
        This function replaces New-PrivateADDecoyComputer for recycling-based decoy deployment.
        It will refuse to modify:
        - Domain Controllers (any detection method)
        - Recently active computers (<90 days since last logon)
        - Computers younger than 90 days
        - Protected infrastructure (DNS, Exchange, DHCP, NPS, ADFS, CA, etc.)
        - Computers in the Domain Controllers OU

        Unconstrained Delegation is a dangerous configuration that allows the computer to cache
        credentials of any user who authenticates to it. Attackers seek these systems for lateral
        movement and credential theft. BloodHound specifically flags these as high-value targets.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADComputer]$ExistingComputer,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter()]
        [switch]$EnableUnconstrainedDelegation,

        [Parameter()]
        [switch]$KeepDisabled,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    process {

        # ------------------------------------------------------------------
        # Module prerequisite check
        # ------------------------------------------------------------------
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "[$($MyInvocation.MyCommand)] - The 'ActiveDirectory' module is not installed. Please install RSAT-AD-Tools."
        }

        # ------------------------------------------------------------------
        # Refresh the computer object with the properties we need for validation
        # ------------------------------------------------------------------
        $getParams = @{
            Identity    = $ExistingComputer
            Properties  = 'Enabled', 'whenCreated', 'PrimaryGroupID', 'OperatingSystem',
                          'DistinguishedName', 'SID', 'Description', 'DNSHostName',
                          'LastLogonDate', 'TrustedForDelegation', 'Name', 'SamAccountName'
            ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Server'))     { $getParams['Server']     = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $getParams['Credential'] = $Credential }

        try {
            $computer = Get-ADComputer @getParams
        }
        catch {
            throw "[$($MyInvocation.MyCommand)] - Failed to retrieve computer '$($ExistingComputer.Name)'. Error: $($_.Exception.Message)"
        }

        Write-Verbose "[$($MyInvocation.MyCommand)] - Validating computer '$($computer.Name)'..."

        # ------------------------------------------------------------------
        # Safety Check 1: Computer must be disabled OR inactive for >= 90 days
        # ------------------------------------------------------------------
        if ($computer.Enabled -eq $true -and
            ($null -eq $computer.LastLogonDate -or
             (Get-Date) - $computer.LastLogonDate -lt [TimeSpan]::FromDays(90))) {
            throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' is enabled and recently active. Only disabled or inactive (>90 days) computers can be recycled."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 1 PASSED: Computer is inactive (Enabled: $($computer.Enabled), LastLogon: $($computer.LastLogonDate))."

        # ------------------------------------------------------------------
        # Safety Check 2: Not a Domain Controller (PrimaryGroupID)
        # ------------------------------------------------------------------
        if ($computer.PrimaryGroupID -eq 516) {
            throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' is a Domain Controller (PrimaryGroupID: 516). Refusing to modify."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 2 PASSED: Not a Domain Controller (PrimaryGroupID: $($computer.PrimaryGroupID))."

        # ------------------------------------------------------------------
        # Safety Check 3: Not a Domain Controller (OperatingSystem)
        # ------------------------------------------------------------------
        if ($computer.OperatingSystem -like "*Domain Controller*" -or
            $computer.OperatingSystem -like "*Server*DC*") {
            throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' appears to be a Domain Controller based on OperatingSystem ('$($computer.OperatingSystem)'). Refusing to modify."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 3 PASSED: Operating System '$($computer.OperatingSystem)' does not indicate a Domain Controller."

        # ------------------------------------------------------------------
        # Safety Check 4: Computer must be at least 90 days old
        # ------------------------------------------------------------------
        $computerAge = (Get-Date) - $computer.whenCreated
        if ($computerAge.TotalDays -lt 90) {
            throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' is only $([math]::Round($computerAge.TotalDays)) days old. Minimum 90 days required for safe recycling."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 4 PASSED: Computer age is $([math]::Round($computerAge.TotalDays)) days (minimum 90 required)."

        # ------------------------------------------------------------------
        # Safety Check 5: Name must not match protected infrastructure patterns
        # ------------------------------------------------------------------
        $protectedPatterns = @(
            '^dc\d*$', '^.*-dc-.*$', '^pdc.*$',         # Domain Controllers
            '^dns.*$', '^.*-dns-.*$',                    # DNS Servers
            '^exch.*$', '^.*-ex-.*$', '^.*mail.*$',     # Exchange
            '^dhcp.*$', '^nps.*$', '^adfs.*$', '^.*-ca-.*$'  # Critical infrastructure
        )
        foreach ($pattern in $protectedPatterns) {
            if ($computer.Name -match $pattern) {
                throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' matches protected infrastructure pattern '$pattern'. Refusing to modify."
            }
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 5 PASSED: Name '$($computer.Name)' does not match any protected infrastructure patterns."

        # ------------------------------------------------------------------
        # Safety Check 6: Not in the Domain Controllers OU
        # ------------------------------------------------------------------
        if ($computer.DistinguishedName -like "*OU=Domain Controllers,*") {
            throw "[$($MyInvocation.MyCommand)] - Computer '$($computer.Name)' is in the Domain Controllers OU ('$($computer.DistinguishedName)'). Refusing to modify."
        }
        Write-Verbose "[$($MyInvocation.MyCommand)] - CHECK 6 PASSED: Computer is not in the Domain Controllers OU."

        # ------------------------------------------------------------------
        # Log original state before any modification
        # ------------------------------------------------------------------
        $rid = $computer.SID.Value.Split('-')[-1]
        Write-Verbose "[$($MyInvocation.MyCommand)] - All safety checks passed. Original state:"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   Name              : $($computer.Name)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   SamAccountName    : $($computer.SamAccountName)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   DistinguishedName : $($computer.DistinguishedName)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   Original RID      : $rid"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   Created           : $($computer.whenCreated)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   OperatingSystem   : $($computer.OperatingSystem)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   Description       : $($computer.Description)"

        # ------------------------------------------------------------------
        # ShouldProcess guard
        # ------------------------------------------------------------------
        $actionDescription = "Transform into decoy with description '$Description'"
        if ($EnableUnconstrainedDelegation) {
            $actionDescription += " and enable Unconstrained Delegation (TrustedForDelegation)"
        }

        if (-not $PSCmdlet.ShouldProcess($computer.DistinguishedName, $actionDescription)) {
            return
        }

        # ------------------------------------------------------------------
        # Build Set-ADComputer parameter hashtable
        # ------------------------------------------------------------------
        $setParams = @{
            Identity    = $computer
            Description = $Description
            ErrorAction = 'Stop'
        }

        if ($PSBoundParameters.ContainsKey('Server'))     { $setParams['Server']     = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $setParams['Credential'] = $Credential }

        # Enable Unconstrained Delegation if requested
        if ($EnableUnconstrainedDelegation) {
            $setParams['TrustedForDelegation'] = $true
            Write-Verbose "[$($MyInvocation.MyCommand)] - Enabling Unconstrained Delegation (TrustedForDelegation = True)."
        }

        # Honour -KeepDisabled:$false (default keeps computer disabled)
        if ($PSBoundParameters.ContainsKey('KeepDisabled') -and (-not $KeepDisabled)) {
            $setParams['Enabled'] = $true
            Write-Verbose "[$($MyInvocation.MyCommand)] - Computer will be ENABLED as -KeepDisabled:`$false was specified."
        }

        # ------------------------------------------------------------------
        # Apply modifications
        # ------------------------------------------------------------------
        Write-Verbose "[$($MyInvocation.MyCommand)] - Modifying description to: '$Description'."

        try {
            Set-ADComputer @setParams
        }
        catch {
            throw "[$($MyInvocation.MyCommand)] - Failed to modify computer '$($computer.Name)'. Error: $($_.Exception.Message)"
        }

        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully modified computer object."

        # ------------------------------------------------------------------
        # Retrieve and return the updated object
        # ------------------------------------------------------------------
        $getFinalParams = @{
            Identity    = $computer
            Properties  = 'whenCreated', 'Description', 'TrustedForDelegation',
                          'Enabled', 'SID', 'LastLogonDate', 'OperatingSystem',
                          'Name', 'SamAccountName', 'DistinguishedName', 'DNSHostName'
            ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Server'))     { $getFinalParams['Server']     = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $getFinalParams['Credential'] = $Credential }

        try {
            $updatedComputer = Get-ADComputer @getFinalParams
        }
        catch {
            throw "[$($MyInvocation.MyCommand)] - Modifications applied but failed to retrieve updated object. Error: $($_.Exception.Message)"
        }

        $updatedRid = $updatedComputer.SID.Value.Split('-')[-1]
        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully recycled computer '$($updatedComputer.Name)' (RID: $updatedRid) created on $($updatedComputer.whenCreated)."

        if ($EnableUnconstrainedDelegation -and $updatedComputer.TrustedForDelegation) {
            Write-Verbose "[$($MyInvocation.MyCommand)] - Unconstrained Delegation is now ENABLED (highly attractive to attackers)."
        }

        return $updatedComputer
    }
}
