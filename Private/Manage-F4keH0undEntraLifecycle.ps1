function Test-PrivateEntraLifecyclePrerequisite {
    [CmdletBinding()]
    param()

    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        throw "[$($MyInvocation.MyCommand)] - Microsoft Graph PowerShell commands are not available. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    try {
        $context = Get-MgContext -ErrorAction Stop
    }
    catch {
        throw "[$($MyInvocation.MyCommand)] - Not connected to Microsoft Graph. Run Connect-MgGraph first."
    }

    if ($null -eq $context) {
        throw "[$($MyInvocation.MyCommand)] - No active Microsoft Graph context found. Run Connect-MgGraph first."
    }

    return $context
}

function Get-PrivateEntraDecoyTypeLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$ObjectType
    )

    switch ($ObjectType) {
        'ServicePrincipal' { return 'EntraServicePrincipalDecoy' }
        'GuestUser' { return 'EntraGuestUserDecoy' }
        'AppRegistration' { return 'EntraAppRegistrationDecoy' }
    }
}

function Resolve-PrivateEntraDecoyObject {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$ObjectType
    )

    $normalizedIdentity = [string]$Identity
    if ([string]::IsNullOrWhiteSpace($normalizedIdentity)) {
        throw "[$($MyInvocation.MyCommand)] - Identity cannot be empty."
    }
    $normalizedIdentity = $normalizedIdentity.Trim()

    switch ($ObjectType) {
        'ServicePrincipal' {
            $properties = 'Id,DisplayName,AppId,AccountEnabled,ServicePrincipalType'
            $resolvedObject = $null

            if ($normalizedIdentity -match '^[0-9a-fA-F-]{36}$') {
                try {
                    $resolvedObject = Get-MgServicePrincipal -ServicePrincipalId $normalizedIdentity -Property $properties -ErrorAction Stop
                }
                catch {
                    $resolvedObject = $null
                }
            }

            if (-not $resolvedObject) {
                $candidateMatches = @(
                    Get-MgServicePrincipal -All -Property $properties -ErrorAction Stop |
                        Where-Object {
                            $_.Id -eq $normalizedIdentity -or
                            $_.AppId -eq $normalizedIdentity -or
                            $_.DisplayName -eq $normalizedIdentity
                        }
                )

                if ($candidateMatches.Count -gt 1) {
                    throw "[$($MyInvocation.MyCommand)] - Identity '$Identity' matches multiple service principals. Use ObjectId or AppId for disambiguation."
                }

                $resolvedObject = $candidateMatches | Select-Object -First 1
            }

            if (-not $resolvedObject) {
                throw "[$($MyInvocation.MyCommand)] - Could not find ServicePrincipal decoy for identity '$Identity'."
            }

            return $resolvedObject
        }

        'GuestUser' {
            $properties = 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,JobTitle,Department'
            $resolvedObject = $null

            try {
                $directUser = Get-MgUser -UserId $normalizedIdentity -Property $properties -ErrorAction Stop
                if ($directUser) {
                    if ($directUser.UserType -ne 'Guest') {
                        throw "[$($MyInvocation.MyCommand)] - Identity '$Identity' resolved to a non-guest user. Use -ObjectType GuestUser only for guest decoys."
                    }

                    $resolvedObject = $directUser
                }
            }
            catch {
                $resolvedObject = $null
            }

            if (-not $resolvedObject) {
                $candidateMatches = @(
                    Get-MgUser -All -Filter "userType eq 'Guest'" -Property $properties -ErrorAction Stop |
                        Where-Object {
                            $_.Id -eq $normalizedIdentity -or
                            $_.UserPrincipalName -eq $normalizedIdentity -or
                            $_.DisplayName -eq $normalizedIdentity
                        }
                )

                if ($candidateMatches.Count -gt 1) {
                    throw "[$($MyInvocation.MyCommand)] - Identity '$Identity' matches multiple guest users. Use ObjectId or UserPrincipalName for disambiguation."
                }

                $resolvedObject = $candidateMatches | Select-Object -First 1
            }

            if (-not $resolvedObject) {
                throw "[$($MyInvocation.MyCommand)] - Could not find GuestUser decoy for identity '$Identity'."
            }

            return $resolvedObject
        }

        'AppRegistration' {
            $properties = 'Id,DisplayName,AppId,Notes'
            $resolvedObject = $null

            if ($normalizedIdentity -match '^[0-9a-fA-F-]{36}$') {
                try {
                    $resolvedObject = Get-MgApplication -ApplicationId $normalizedIdentity -Property $properties -ErrorAction Stop
                }
                catch {
                    $resolvedObject = $null
                }
            }

            if (-not $resolvedObject) {
                $candidateMatches = @(
                    Get-MgApplication -All -Property $properties -ErrorAction Stop |
                        Where-Object {
                            $_.Id -eq $normalizedIdentity -or
                            $_.AppId -eq $normalizedIdentity -or
                            $_.DisplayName -eq $normalizedIdentity
                        }
                )

                if ($candidateMatches.Count -gt 1) {
                    throw "[$($MyInvocation.MyCommand)] - Identity '$Identity' matches multiple app registrations. Use ObjectId or AppId for disambiguation."
                }

                $resolvedObject = $candidateMatches | Select-Object -First 1
            }

            if (-not $resolvedObject) {
                throw "[$($MyInvocation.MyCommand)] - Could not find AppRegistration decoy for identity '$Identity'."
            }

            return $resolvedObject
        }
    }
}

function Get-PrivateEntraDecoyObjectById {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$ObjectType
    )

    switch ($ObjectType) {
        'ServicePrincipal' {
            return Get-MgServicePrincipal -ServicePrincipalId $ObjectId -Property 'Id,DisplayName,AppId,AccountEnabled,ServicePrincipalType' -ErrorAction Stop
        }
        'GuestUser' {
            return Get-MgUser -UserId $ObjectId -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,JobTitle,Department' -ErrorAction Stop
        }
        'AppRegistration' {
            return Get-MgApplication -ApplicationId $ObjectId -Property 'Id,DisplayName,AppId,Notes' -ErrorAction Stop
        }
    }
}

function Get-PrivateEntraDecoyEventContext {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ServicePrincipal', 'GuestUser', 'AppRegistration')]
        [string]$ObjectType,

        [Parameter(Mandatory = $true)]
        [PSObject]$Object
    )

    switch ($ObjectType) {
        'ServicePrincipal' {
            return [PSCustomObject]@{
                Identity    = if ($Object.AppId) { [string]$Object.AppId } else { [string]$Object.Id }
                DisplayName = [string]$Object.DisplayName
                Location    = "ServicePrincipalId:$($Object.Id)"
                Status      = if ($Object.AccountEnabled -eq $true) { 'Enabled' } else { 'Disabled' }
            }
        }

        'GuestUser' {
            return [PSCustomObject]@{
                Identity    = if ($Object.UserPrincipalName) { [string]$Object.UserPrincipalName } else { [string]$Object.Id }
                DisplayName = [string]$Object.DisplayName
                Location    = "UserId:$($Object.Id)"
                Status      = if ($Object.AccountEnabled -eq $true) { 'Enabled' } else { 'Disabled' }
            }
        }

        'AppRegistration' {
            return [PSCustomObject]@{
                Identity    = if ($Object.AppId) { [string]$Object.AppId } else { [string]$Object.Id }
                DisplayName = [string]$Object.DisplayName
                Location    = "ApplicationId:$($Object.Id)"
                Status      = 'Present'
            }
        }
    }
}
