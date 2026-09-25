<#
.SYNOPSIS
    Creates a brand-new AD decoy user object.

.DESCRIPTION
    Used by New-F4keH0undDecoy's Create-mode fallback path when no existing
    disabled/stale account is available to recycle (see
    Find-F4keH0undRecyclableObject). When a suitable existing account IS
    available, prefer Set-PrivateADDecoyUser instead: it recycles the object
    in place, preserving its original RID and whenCreated metadata, which is
    harder for an attacker to fingerprint than a freshly created object with
    a high sequential RID and a recent creation timestamp.

    PREFERENCE ORDER (used automatically by New-F4keH0undDecoy -PreferRecycling):
        1. Set-PrivateADDecoyUser (recycle) - when a recyclable candidate exists.
        2. New-PrivateADDecoyUser (this function, create) - fallback only.

    SEE ALSO:
        Private/Set-PrivateADDecoyUser.ps1
        Private/Find-F4keH0undRecyclableObject.ps1
#>

function New-PrivateADDecoyUser {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "[$($MyInvocation.MyCommand)] - The 'ActiveDirectory' module is not installed. Please install RSAT-AD-Tools."
        return
    }

    # Build a cryptographically random 30-character password directly as a SecureString
    # (never materialized as a plaintext [string]) to satisfy PSAvoidUsingConvertToSecureStringWithPlainText.
    $charPool = (48..57) + (65..90) + (97..122)
    $securePassword = [System.Security.SecureString]::new()
    1..30 | ForEach-Object { $securePassword.AppendChar([char]($charPool | Get-Random)) }
    $securePassword.MakeReadOnly()

    $domainParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $domainParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $domainParams['Credential'] = $Credential }

    $upnSuffix = (Get-ADDomain @domainParams).UserPrincipalName
    $userPrincipalName = "$($SamAccountName)@$($upnSuffix)"

    if (-not $PSCmdlet.ShouldProcess($SamAccountName, "Create new AD decoy user")) {
        return
    }

    try {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Creating AD User '$Name' with SAMAccountName '$SamAccountName'."
        
        $adUserParams = @{
            Name                  = $Name
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $userPrincipalName
            Description           = $Description
            AccountPassword       = $securePassword
            Enabled               = $false
            PasswordNeverExpires  = $true
            ChangePasswordAtLogon = $false
            PassThru              = $true
            ErrorAction           = 'Stop'
        }

        if ($PSBoundParameters.ContainsKey('Credential')) { $adUserParams['Credential'] = $Credential }
        if ($PSBoundParameters.ContainsKey('Server')) { $adUserParams['Server'] = $Server }

        $newUser = New-ADUser @adUserParams

        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully created user '$($newUser.DistinguishedName)'."
        return $newUser
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to create AD user '$Name'. Error: $($_.Exception.Message)"
        return $null
    }
}