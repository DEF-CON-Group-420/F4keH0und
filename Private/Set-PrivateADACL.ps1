function Set-PrivateADACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$TargetObject,
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$Principal,
        [Parameter(Mandatory=$true)]
        [string]$Permission,
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter()]
        [string]$Server
    )

    $adParams = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $adParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }
    
    try {
        Write-Verbose "[$($MyInvocation.MyCommand)] - Setting '$Permission' for '$($Principal.SamAccountName)' on '$($TargetObject.Name)'"
        
        # Get the object's current security descriptor (ACL)
        $getParams = $adParams.Clone()
        $getParams['Identity'] = $TargetObject.DistinguishedName
        $getParams['Properties'] = 'nTSecurityDescriptor'
        $sd = (Get-ADGroup @getParams).nTSecurityDescriptor

        # Define the permission to grant
        $permissionMap = @{
            "WriteMembers" = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
        }
        # This GUID represents the "Member" property of a group.
        $propertyGuid = [guid]'{bf9679c0-0de6-11d0-a285-00aa003049e2}'

        # Create a new Access Control Rule
        $newRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Principal.SID,
            $permissionMap[$Permission],
            [System.Security.AccessControl.AccessControlType]::Allow,
            $propertyGuid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        )

        # Add the new rule to the security descriptor
        $sd.AddAccessRule($newRule)

        # Apply the modified security descriptor to the target object
        $setParams = $adParams.Clone()
        $setParams['Identity'] = $TargetObject.DistinguishedName
        $setParams['SecurityDescriptor'] = $sd
        
        Set-ADObject @setParams

        Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully set ACL."
        return $true
    }
    catch {
        Write-Error "[$($MyInvocation.MyCommand)] - Failed to set ACL. Error: $($_.Exception.Message)"
        return $false
    }
}
