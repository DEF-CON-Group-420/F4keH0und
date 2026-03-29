<#
.SYNOPSIS
    Safely removes a decoy object and its associated relationships from Active Directory.
.DESCRIPTION
    This function finds a specified decoy user in Active Directory, removes it from any groups
    it is a member of, and then deletes the user object itself.
    It fully supports -WhatIf, -Confirm, -Server, and -Credential for operational safety.
.PARAMETER Identity
    The SamAccountName of the decoy user you want to remove.
.PARAMETER Server
    Specify a Domain Controller to run all AD commands against. Required for cross-domain operations.
.PARAMETER Credential
    Provide the credentials of a privileged account. Required for cross-domain operations.
.EXAMPLE
    PS C:\> Remove-F4keH0undDecoy -Identity "decoy_admin" -Server "DC01.target.local" -Credential (Get-Credential) -WhatIf

    Performs a dry run of removing the "decoy_admin" user from the target.local domain.
#>
function Remove-F4keH0undDecoy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateSet("User", "Computer", "Group")]
        [string]$DecoyType = "User"
    )

    process {
    $adParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Attempting to find decoy '$Identity'."
    $decoyObject = $null
    try {
        switch ($DecoyType) {
            "User" {
                $findParams = $adParams.Clone()
                $findParams['Identity'] = $Identity
                $findParams['Properties'] = "MemberOf"
                $findParams['ErrorAction'] = "Stop"
                $decoyObject = Get-ADUser @findParams
            }
        }
    }
    catch { Write-Error "[ERROR] Failed to find a decoy with Identity '$Identity' and Type '$DecoyType'. Error: $($_.Exception.Message)"; return }
    if ($null -eq $decoyObject) { Write-Error "[ERROR] Could not find a decoy with Identity '$Identity' and Type '$DecoyType'."; return }
    Write-Host "[INFO] Found decoy: $($decoyObject.DistinguishedName)" -ForegroundColor Cyan

    if ($decoyObject.MemberOf.Count -gt 0) {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Decoy is a member of $($decoyObject.MemberOf.Count) groups. Removing memberships..."
        foreach ($groupDN in $decoyObject.MemberOf) {
            $target = "Group '$($groupDN)'"; $action = "Remove member '$($decoyObject.Name)' from"
            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    $removeMemberParams = $adParams.Clone()
                    $removeMemberParams['Identity'] = $groupDN
                    $removeMemberParams['Members'] = $decoyObject
                    $removeMemberParams['Confirm'] = $false
                    $removeMemberParams['ErrorAction'] = "Stop"
                    Remove-ADGroupMember @removeMemberParams
                    Write-Host "[SUCCESS] Removed decoy from group '$($groupDN)'."
                }
                catch { Write-Warning "[WARNING] Failed to remove decoy from group '$($groupDN)'. Error: $($_.Exception.Message)" }
            }
        }
    }
    $target = $decoyObject.DistinguishedName; $action = "Remove Decoy Object"
    if ($PSCmdlet.ShouldProcess($target, $action)) {
        try {
            $removeUserParams = $adParams.Clone()
            $removeUserParams['Identity'] = $decoyObject
            $removeUserParams['Confirm'] = $false
            $removeUserParams['ErrorAction'] = "Stop"
            Remove-ADUser @removeUserParams
            Write-Host "[SUCCESS] Successfully removed decoy '$($decoyObject.Name)'." -ForegroundColor Green
        }
        catch { Write-Error "[ERROR] Failed to remove decoy. Error: $($_.Exception.Message)" }
    }
    } # end process
}