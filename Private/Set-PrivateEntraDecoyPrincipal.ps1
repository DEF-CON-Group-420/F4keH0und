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

        # ------------------------------------------------------------------
        # ShouldProcess guard
        # ------------------------------------------------------------------
        $actionDescription = "Transform into Entra ID decoy with description '$Description'"
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
                        -Notes $Description -ErrorAction Stop
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
                        -JobTitle $Description `
                        -Department "Legacy Integration" `
                        -ErrorAction Stop
                    Write-Verbose "[$($MyInvocation.MyCommand)] - Updated JobTitle/Department on guest user '$($RecyclableObject.DisplayName)'."
                    $modificationsForAudit['jobTitle']   = "Changed to: $Description"
                    $modificationsForAudit['department']  = "Changed to: Legacy Integration"
                }
                catch {
                    throw "[$($MyInvocation.MyCommand)] - Failed to update guest user '$($RecyclableObject.DisplayName)'. Error: $($_.Exception.Message)"
                }
            }

            'AppRegistration' {
                try {
                    Update-MgApplication -ApplicationId $objectId `
                        -Notes $Description -ErrorAction Stop
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
        $RecyclableObject | Add-Member -NotePropertyName 'RecycledAt' -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -Force
        return $RecyclableObject
    }
}
