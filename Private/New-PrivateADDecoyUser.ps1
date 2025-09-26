function New-PrivateADDecoyUser {
    [CmdletBinding()]
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

    $password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 30 | ForEach-Object { [char]$_ })
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

    $domainParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $domainParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $domainParams['Credential'] = $Credential }
    
    $upnSuffix = (Get-ADDomain @domainParams).UserPrincipalName
    $userPrincipalName = "$($SamAccountName)@$($upnSuffix)"

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