function Set-PrivateADDecoySPN {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,

        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server
    )

    Write-Verbose "[$($MyInvocation.MyCommand)] - Setting SPN '$($ServicePrincipalName)' for user '$($User.SamAccountName)'."

    if (-not $PSCmdlet.ShouldProcess($User.SamAccountName, "Add SPN '$ServicePrincipalName'")) {
        return $false
    }

    try {
        $spnParams = @{
            Identity             = $User
            ServicePrincipalName = @{Add = $ServicePrincipalName }
            ErrorAction          = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Credential')) { $spnParams['Credential'] = $Credential }
        if ($PSBoundParameters.ContainsKey('Server')) { $spnParams['Server'] = $Server }

        Set-ADUser @spnParams
        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully set SPN."
        return $true
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to set SPN for user '$($User.SamAccountName)'. Error: $($_.Exception.Message)"
        return $false
    }
}