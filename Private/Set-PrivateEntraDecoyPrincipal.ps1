function Set-PrivateEntraDecoyPrincipal {
    <#
    .SYNOPSIS
        Recycles an existing disabled or inactive Entra ID (Azure AD) service principal,
        guest user, or app registration by transforming it into a cloud-based decoy.

    .DESCRIPTION
        This function modifies an existing Entra ID object discovered by
        Find-F4keH0undRecyclableEntraObject to serve as a deception decoy.

        Supported object types and their modifications:

        ServicePrincipal:
        - Updates the Notes / Description property to a decoy description.
        - Optionally assigns a high-privilege directory role (e.g., Global Reader, Application
          Administrator) to make the principal appear as a high-value target for attackers
          performing OAuth / service-principal enumeration.

        GuestUser:
        - Updates the JobTitle and Department attributes to match the decoy persona.
        - Optionally updates OfficeLocation for additional identity realism.
        - Preserves original UPN, display name, and object ID.

        AppRegistration:
        - Updates the Notes field of the application.
        - Optionally adds a decoy OAuth2 permission scope to attract attackers performing
          consent-grant hunting.

        After modification, an audit entry is written to AuditLogPath (if specified).

        Safety checks ensure the function will not modify:
        - Currently enabled service principals with recent activity.
        - Privileged role holders (Global Administrator, Privileged Role Administrator).
        - Microsoft-owned first-party application service principals.

    .PARAMETER RecyclableObject
        The object returned by Find-F4keH0undRecyclableEntraObject to recycle.
        Must have ObjectType of 'ServicePrincipal', 'GuestUser', or 'AppRegistration'.

    .PARAMETER Description
        The decoy description to apply to the object. Used to update the Notes or
        JobTitle/Department attributes depending on object type.

    .PARAMETER AssignHighPrivilegeRole
        When specified for ServicePrincipal objects, assigns a high-privilege Entra directory
        role (Application Administrator) to the service principal to make it an attractive
        target. WARNING: This will make the principal able to manage app registrations.
        Use only in lab or tightly controlled environments.

    .PARAMETER LureTheme
        Optional theme label (for example RoleAssignmentLure, OAuthConsentTrap,
        ConditionalAccessBypassBait). Stored in metadata and appended to notes-based
        descriptions where supported.

    .PARAMETER RoleAssignmentHint
        Optional role-assignment lure text appended to notes metadata where supported.

    .PARAMETER ConsentScopeBait
        Optional OAuth consent lure text appended to notes metadata where supported.

    .PARAMETER ConditionalAccessBypassHint
        Optional conditional-access hint text appended to notes metadata where supported.

    .PARAMETER SecretHint
        Optional stale-secret/certificate lure hint appended to notes metadata where supported.

    .PARAMETER OAuthPermissionBait
        Optional OAuth permission-bundle lure text appended to notes metadata where supported.

    .PARAMETER OAuthGrantTypeBait
        Optional OAuth grant-type lure text appended to notes metadata where supported.

    .PARAMETER OAuthResourceBait
        Optional OAuth resource/API lure text appended to notes metadata where supported.

    .PARAMETER OAuthRedirectUriBait
        Optional OAuth redirect-URI lure text appended to notes metadata where supported.

    .PARAMETER OAuthAdminConsentHint
        Optional OAuth admin-consent lure text appended to notes metadata where supported.

    .PARAMETER PersonaJobTitle
        Optional guest-user persona job title override. If omitted for guest-user decoys,
        `Description` is used as `JobTitle`.

    .PARAMETER PersonaDepartment
        Optional guest-user persona department override. If omitted for guest-user decoys,
        defaults to `Legacy Integration`.

    .PARAMETER PersonaOfficeLocation
        Optional guest-user office-location override. If omitted for guest-user decoys,
        defaults to `Hybrid/Remote`.

    .PARAMETER IdentityOwnerHint
        Optional identity owner hint appended to notes metadata where supported.

    .PARAMETER GroupHint
        Optional group/team hint appended to notes metadata where supported.

    .PARAMETER AuditLogPath
        Optional path to a JSON audit log file. When specified, an audit entry is appended
        after successful modification.

    .EXAMPLE
        $recyclable = Find-F4keH0undRecyclableEntraObject -IncludeServicePrincipals |
                          Select-Object -First 1
        Set-PrivateEntraDecoyPrincipal -RecyclableObject $recyclable `
            -Description "Legacy BI Analytics Connector" -Verbose

    .EXAMPLE
        # Make a service principal appear high-value to cloud attackers
        Set-PrivateEntraDecoyPrincipal -RecyclableObject $recyclable `
            -Description "Power BI Enterprise Service" `
            -AssignHighPrivilegeRole `
            -AuditLogPath "C:\Logs\f4keh0und_audit.json"

    .NOTES
        Requires the Microsoft.Graph.Applications and Microsoft.Graph.Identity.DirectoryManagement
        modules and an active Connect-MgGraph session with Application.ReadWrite.All and
        RoleManagement.ReadWrite.Directory permissions (the latter only if
        -AssignHighPrivilegeRole is used).

        This function does NOT change the object's enabled state, credentials, redirect URIs,
        or any security-sensitive properties beyond those listed above. The goal is cosmetic
        transformation that makes the object appear to be a forgotten but important workload.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$RecyclableObject,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter()]
        [switch]$AssignHighPrivilegeRole,

        [Parameter()]
        [string]$LureTheme,

        [Parameter()]
        [string]$RoleAssignmentHint,

        [Parameter()]
        [string]$ConsentScopeBait,

        [Parameter()]
        [string]$ConditionalAccessBypassHint,

        [Parameter()]
        [string]$SecretHint,

        [Parameter()]
        [string]$OAuthPermissionBait,

        [Parameter()]
        [string]$OAuthGrantTypeBait,

        [Parameter()]
        [string]$OAuthResourceBait,

        [Parameter()]
        [string]$OAuthRedirectUriBait,

        [Parameter()]
        [string]$OAuthAdminConsentHint,

        [Parameter()]
        [string]$PersonaJobTitle,

        [Parameter()]
        [string]$PersonaDepartment,

        [Parameter()]
        [string]$PersonaOfficeLocation,

        [Parameter()]
        [string]$IdentityOwnerHint,

        [Parameter()]
        [string]$GroupHint,

        [Parameter()]
        [string]$AuditLogPath
    )

    process {

        # ------------------------------------------------------------------
        # Module prerequisite check
        # ------------------------------------------------------------------
        $requiredModules = @('Microsoft.Graph.Applications')
        foreach ($mod in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $mod) -and
                -not (Get-Module -ListAvailable -Name 'Microsoft.Graph')) {
                throw "[$($MyInvocation.MyCommand)] - Required module '$mod' is not installed. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
            }
        }

        # Ensure active Graph session
        try {
            $ctx = Get-MgContext -ErrorAction Stop
            if (-not $ctx) { throw "No active context." }
        }
        catch {
            throw "[$($MyInvocation.MyCommand)] - Not connected to Microsoft Graph. Run Connect-MgGraph first."
        }

        # ------------------------------------------------------------------
        # Validate input object type
        # ------------------------------------------------------------------
        $validTypes = @('ServicePrincipal', 'GuestUser', 'AppRegistration')
        if ($RecyclableObject.ObjectType -notin $validTypes) {
            throw "[$($MyInvocation.MyCommand)] - Unsupported ObjectType '$($RecyclableObject.ObjectType)'. Must be one of: $($validTypes -join ', ')."
        }

        $objectId   = $RecyclableObject.ObjectId
        $objectType = $RecyclableObject.ObjectType

        Write-Verbose "[$($MyInvocation.MyCommand)] - Processing $objectType '$($RecyclableObject.DisplayName)' (ID: $objectId)..."

        # ------------------------------------------------------------------
        # Safety Check: Do not modify enabled service principals
        # ------------------------------------------------------------------
        if ($objectType -eq 'ServicePrincipal' -and $RecyclableObject.AccountEnabled -eq $true) {
            throw "[$($MyInvocation.MyCommand)] - Service principal '$($RecyclableObject.DisplayName)' is currently enabled. Only disabled service principals can be recycled."
        }

        # ------------------------------------------------------------------
        # Safety Check: Do not modify Microsoft first-party service principals
        # ------------------------------------------------------------------
        if ($objectType -in @('ServicePrincipal', 'AppRegistration')) {
            $microsoftPublisherIds = @(
                'f8cdef31-a31e-4b4a-93e4-5f571e91255a',   # Microsoft Services
                '72f988bf-86f1-41af-91ab-2d7cd011db47'    # Microsoft
            )
            try {
                if ($objectType -eq 'ServicePrincipal') {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $objectId -Property 'AppOwnerOrganizationId' -ErrorAction Stop
                    if ($sp.AppOwnerOrganizationId -in $microsoftPublisherIds) {
                        throw "[$($MyInvocation.MyCommand)] - Service principal '$($RecyclableObject.DisplayName)' is owned by Microsoft (AppOwnerOrganizationId: $($sp.AppOwnerOrganizationId)). Refusing to modify."
                    }
                }
            }
            catch {
                if ($_.Exception.Message -like "*Refusing to modify*") { throw }
                Write-Warning "[$($MyInvocation.MyCommand)] - Could not verify publisher identity for '$($RecyclableObject.DisplayName)': $($_.Exception.Message)"
            }
        }

        # ------------------------------------------------------------------
        # Log original state
        # ------------------------------------------------------------------
        Write-Verbose "[$($MyInvocation.MyCommand)] - All safety checks passed. Original state:"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   ObjectType     : $objectType"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   DisplayName    : $($RecyclableObject.DisplayName)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   ObjectId       : $objectId"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   Created        : $($RecyclableObject.CreatedDateTime)"
        Write-Verbose "[$($MyInvocation.MyCommand)] -   LastSignIn     : $($RecyclableObject.LastSignInDateTime)"

        $originalStateForAudit = @{
            displayName       = $RecyclableObject.DisplayName
            objectType        = $objectType
            accountEnabled    = $RecyclableObject.AccountEnabled
            createdDateTime   = if ($RecyclableObject.CreatedDateTime) { $RecyclableObject.CreatedDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            lastSignInDateTime = if ($RecyclableObject.LastSignInDateTime) { $RecyclableObject.LastSignInDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
        }

        $modificationsForAudit = @{
            description = "Changed to: $Description"
        }

        if ($PSBoundParameters.ContainsKey('LureTheme') -and -not [string]::IsNullOrWhiteSpace($LureTheme)) {
            $modificationsForAudit['LureTheme'] = $LureTheme
        }
        if ($PSBoundParameters.ContainsKey('RoleAssignmentHint') -and -not [string]::IsNullOrWhiteSpace($RoleAssignmentHint)) {
            $modificationsForAudit['RoleAssignmentHint'] = $RoleAssignmentHint
        }
        if ($PSBoundParameters.ContainsKey('ConsentScopeBait') -and -not [string]::IsNullOrWhiteSpace($ConsentScopeBait)) {
            $modificationsForAudit['ConsentScopeBait'] = $ConsentScopeBait
        }
        if ($PSBoundParameters.ContainsKey('ConditionalAccessBypassHint') -and -not [string]::IsNullOrWhiteSpace($ConditionalAccessBypassHint)) {
            $modificationsForAudit['ConditionalAccessBypassHint'] = $ConditionalAccessBypassHint
        }
        if ($PSBoundParameters.ContainsKey('SecretHint') -and -not [string]::IsNullOrWhiteSpace($SecretHint)) {
            $modificationsForAudit['SecretHint'] = $SecretHint
        }
        if ($PSBoundParameters.ContainsKey('OAuthPermissionBait') -and -not [string]::IsNullOrWhiteSpace($OAuthPermissionBait)) {
            $modificationsForAudit['OAuthPermissionBait'] = $OAuthPermissionBait
        }
        if ($PSBoundParameters.ContainsKey('OAuthGrantTypeBait') -and -not [string]::IsNullOrWhiteSpace($OAuthGrantTypeBait)) {
            $modificationsForAudit['OAuthGrantTypeBait'] = $OAuthGrantTypeBait
        }
        if ($PSBoundParameters.ContainsKey('OAuthResourceBait') -and -not [string]::IsNullOrWhiteSpace($OAuthResourceBait)) {
            $modificationsForAudit['OAuthResourceBait'] = $OAuthResourceBait
        }
        if ($PSBoundParameters.ContainsKey('OAuthRedirectUriBait') -and -not [string]::IsNullOrWhiteSpace($OAuthRedirectUriBait)) {
            $modificationsForAudit['OAuthRedirectUriBait'] = $OAuthRedirectUriBait
        }
        if ($PSBoundParameters.ContainsKey('OAuthAdminConsentHint') -and -not [string]::IsNullOrWhiteSpace($OAuthAdminConsentHint)) {
            $modificationsForAudit['OAuthAdminConsentHint'] = $OAuthAdminConsentHint
        }
        if ($PSBoundParameters.ContainsKey('IdentityOwnerHint') -and -not [string]::IsNullOrWhiteSpace($IdentityOwnerHint)) {
            $modificationsForAudit['IdentityOwnerHint'] = $IdentityOwnerHint
        }
        if ($PSBoundParameters.ContainsKey('GroupHint') -and -not [string]::IsNullOrWhiteSpace($GroupHint)) {
            $modificationsForAudit['GroupHint'] = $GroupHint
        }

        $notesDetailLines = [System.Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($LureTheme)) {
            $notesDetailLines.Add("Theme: $LureTheme")
        }
        if (-not [string]::IsNullOrWhiteSpace($RoleAssignmentHint)) {
            $notesDetailLines.Add("RoleAssignmentHint: $RoleAssignmentHint")
        }
        if (-not [string]::IsNullOrWhiteSpace($ConsentScopeBait)) {
            $notesDetailLines.Add("ConsentScopeBait: $ConsentScopeBait")
        }
        if (-not [string]::IsNullOrWhiteSpace($ConditionalAccessBypassHint)) {
            $notesDetailLines.Add("ConditionalAccessBypassHint: $ConditionalAccessBypassHint")
        }
        if (-not [string]::IsNullOrWhiteSpace($SecretHint)) {
            $notesDetailLines.Add("SecretHint: $SecretHint")
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthPermissionBait)) {
            $notesDetailLines.Add("OAuthPermissionBait: $OAuthPermissionBait")
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthGrantTypeBait)) {
            $notesDetailLines.Add("OAuthGrantTypeBait: $OAuthGrantTypeBait")
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthResourceBait)) {
            $notesDetailLines.Add("OAuthResourceBait: $OAuthResourceBait")
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthRedirectUriBait)) {
            $notesDetailLines.Add("OAuthRedirectUriBait: $OAuthRedirectUriBait")
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthAdminConsentHint)) {
            $notesDetailLines.Add("OAuthAdminConsentHint: $OAuthAdminConsentHint")
        }
        if (-not [string]::IsNullOrWhiteSpace($IdentityOwnerHint)) {
            $notesDetailLines.Add("IdentityOwnerHint: $IdentityOwnerHint")
        }
        if (-not [string]::IsNullOrWhiteSpace($GroupHint)) {
            $notesDetailLines.Add("GroupHint: $GroupHint")
        }

        $effectiveDescription = if ($notesDetailLines.Count -gt 0) {
            "$Description`n$($notesDetailLines -join "`n")"
        }
        else {
            $Description
        }

        $resolvedGuestJobTitle = if (-not [string]::IsNullOrWhiteSpace($PersonaJobTitle)) {
            $PersonaJobTitle
        }
        else {
            $Description
        }

        $resolvedGuestDepartment = if (-not [string]::IsNullOrWhiteSpace($PersonaDepartment)) {
            $PersonaDepartment
        }
        else {
            'Legacy Integration'
        }

        $resolvedGuestOfficeLocation = if (-not [string]::IsNullOrWhiteSpace($PersonaOfficeLocation)) {
            $PersonaOfficeLocation
        }
        else {
            'Hybrid/Remote'
        }

        # ------------------------------------------------------------------
        # ShouldProcess guard
        # ------------------------------------------------------------------
        $actionDescription = "Transform into Entra ID decoy with description '$Description'"
        if (-not [string]::IsNullOrWhiteSpace($LureTheme)) {
            $actionDescription += " (theme: $LureTheme)"
        }
        if ($AssignHighPrivilegeRole) {
            $actionDescription += " and assign Application Administrator role"
        }

        if (-not $PSCmdlet.ShouldProcess("$objectType '$($RecyclableObject.DisplayName)' ($objectId)", $actionDescription)) {
            return
        }

        # ------------------------------------------------------------------
        # Apply modifications based on object type
        # ------------------------------------------------------------------
        switch ($objectType) {

            'ServicePrincipal' {
                try {
                    Update-MgServicePrincipal -ServicePrincipalId $objectId `
                        -Notes $effectiveDescription -ErrorAction Stop
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Updated Notes on service principal '$($RecyclableObject.DisplayName)'."
                }
                catch {
                    throw "[$($MyInvocation.MyCommand)] - Failed to update service principal '$($RecyclableObject.DisplayName)'. Error: $($_.Exception.Message)"
                }

                # Optionally assign high-privilege role
                if ($AssignHighPrivilegeRole) {
                    try {
                        $roleName = 'Application Administrator'
                        $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction Stop |
                                    Select-Object -First 1

                        if (-not $role) {
                            # Activate the role template if not yet instantiated
                            $roleTemplate = Get-MgDirectoryRoleTemplate -ErrorAction Stop |
                                                Where-Object { $_.DisplayName -eq $roleName } |
                                                Select-Object -First 1
                            if ($roleTemplate) {
                                $role = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id -ErrorAction Stop
                            }
                        }

                        if ($role) {
                            $memberRef = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$objectId" }
                            New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -BodyParameter $memberRef -ErrorAction Stop
                            Write-Verbose "[$($MyInvocation.MyCommand)] - Assigned '$roleName' role to service principal '$($RecyclableObject.DisplayName)'."
                            $modificationsForAudit['roleAssignment'] = "Added: $roleName"
                        }
                        else {
                            Write-Warning "[$($MyInvocation.MyCommand)] - Could not find or activate the '$roleName' directory role. Skipping role assignment."
                        }
                    }
                    catch {
                        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to assign high-privilege role: $($_.Exception.Message)"
                    }
                }
            }

            'GuestUser' {
                try {
                    Update-MgUser -UserId $objectId `
                        -JobTitle $resolvedGuestJobTitle `
                        -Department $resolvedGuestDepartment `
                        -OfficeLocation $resolvedGuestOfficeLocation `
                        -ErrorAction Stop
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Updated JobTitle/Department/OfficeLocation on guest user '$($RecyclableObject.DisplayName)'."
                    $modificationsForAudit['jobTitle']   = "Changed to: $resolvedGuestJobTitle"
                    $modificationsForAudit['department']  = "Changed to: $resolvedGuestDepartment"
                    $modificationsForAudit['officeLocation'] = "Changed to: $resolvedGuestOfficeLocation"
                }
                catch {
                    throw "[$($MyInvocation.MyCommand)] - Failed to update guest user '$($RecyclableObject.DisplayName)'. Error: $($_.Exception.Message)"
                }
            }

            'AppRegistration' {
                try {
                    Update-MgApplication -ApplicationId $objectId `
                        -Notes $effectiveDescription -ErrorAction Stop
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Updated Notes on app registration '$($RecyclableObject.DisplayName)'."
                }
                catch {
                    throw "[$($MyInvocation.MyCommand)] - Failed to update app registration '$($RecyclableObject.DisplayName)'. Error: $($_.Exception.Message)"
                }
            }
        }

        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully recycled Entra $objectType '$($RecyclableObject.DisplayName)' (ID: $objectId)."

        # ------------------------------------------------------------------
        # Write audit log entry
        # ------------------------------------------------------------------
        if ($PSBoundParameters.ContainsKey('AuditLogPath') -and -not [string]::IsNullOrWhiteSpace($AuditLogPath)) {
            Write-F4keH0undAuditLog `
                -AuditLogPath  $AuditLogPath `
                -Operation     'RecycleEntraPrincipal' `
                -ObjectGuid    $objectId `
                -Source        'Entra' `
                -OriginalState $originalStateForAudit `
                -Modifications $modificationsForAudit
        }

        # Return the input object (enriched with modification metadata) so the caller
        # can track what was recycled.
        $RecyclableObject | Add-Member -NotePropertyName 'DecoyDescription' -NotePropertyValue $Description -Force
        if (-not [string]::IsNullOrWhiteSpace($LureTheme)) {
            $RecyclableObject | Add-Member -NotePropertyName 'LureTheme' -NotePropertyValue $LureTheme -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($ConsentScopeBait)) {
            $RecyclableObject | Add-Member -NotePropertyName 'ConsentScopeBait' -NotePropertyValue $ConsentScopeBait -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($ConditionalAccessBypassHint)) {
            $RecyclableObject | Add-Member -NotePropertyName 'ConditionalAccessBypassHint' -NotePropertyValue $ConditionalAccessBypassHint -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($SecretHint)) {
            $RecyclableObject | Add-Member -NotePropertyName 'SecretHint' -NotePropertyValue $SecretHint -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthPermissionBait)) {
            $RecyclableObject | Add-Member -NotePropertyName 'OAuthPermissionBait' -NotePropertyValue $OAuthPermissionBait -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthGrantTypeBait)) {
            $RecyclableObject | Add-Member -NotePropertyName 'OAuthGrantTypeBait' -NotePropertyValue $OAuthGrantTypeBait -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthResourceBait)) {
            $RecyclableObject | Add-Member -NotePropertyName 'OAuthResourceBait' -NotePropertyValue $OAuthResourceBait -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthRedirectUriBait)) {
            $RecyclableObject | Add-Member -NotePropertyName 'OAuthRedirectUriBait' -NotePropertyValue $OAuthRedirectUriBait -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($OAuthAdminConsentHint)) {
            $RecyclableObject | Add-Member -NotePropertyName 'OAuthAdminConsentHint' -NotePropertyValue $OAuthAdminConsentHint -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($IdentityOwnerHint)) {
            $RecyclableObject | Add-Member -NotePropertyName 'IdentityOwnerHint' -NotePropertyValue $IdentityOwnerHint -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($GroupHint)) {
            $RecyclableObject | Add-Member -NotePropertyName 'GroupHint' -NotePropertyValue $GroupHint -Force
        }
        if ($objectType -eq 'GuestUser') {
            $RecyclableObject | Add-Member -NotePropertyName 'PersonaOfficeLocation' -NotePropertyValue $resolvedGuestOfficeLocation -Force
        }
        $RecyclableObject | Add-Member -NotePropertyName 'RecycledAt' -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -Force
        return $RecyclableObject
    }
}
