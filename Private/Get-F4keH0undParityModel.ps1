function Get-F4keH0undParityModel {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param()

    $lifecycleActions = @('Deploy', 'Update', 'Disable', 'Enable', 'Remove')

    $decoyTypes = @(
        [PSCustomObject]@{
            DecoyType       = 'StaleAdminLure'
            Platform        = 'AD'
            ObjectType      = 'User'
            Family          = 'IdentityAdmin'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'KerberoastableUser'
            Platform        = 'AD'
            ObjectType      = 'User'
            Family          = 'ServiceAuth'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'DNSAdminUser'
            Platform        = 'AD'
            ObjectType      = 'User'
            Family          = 'IdentityAdmin'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'UnconstrainedDelegationComputer'
            Platform        = 'AD'
            ObjectType      = 'Computer'
            Family          = 'ServiceAuth'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'ACLAttackPath'
            Platform        = 'AD'
            ObjectType      = 'Group'
            Family          = 'AppPath'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $false
            SupportsEnable  = $false
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'EntraServicePrincipalDecoy'
            Platform        = 'Entra'
            ObjectType      = 'ServicePrincipal'
            Family          = 'ServiceAuth'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'EntraGuestUserDecoy'
            Platform        = 'Entra'
            ObjectType      = 'GuestUser'
            Family          = 'IdentityAdmin'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $true
            SupportsEnable  = $true
            SupportsRemove  = $true
        }
        [PSCustomObject]@{
            DecoyType       = 'EntraAppRegistrationDecoy'
            Platform        = 'Entra'
            ObjectType      = 'AppRegistration'
            Family          = 'AppPath'
            SupportsDeploy  = $true
            SupportsUpdate  = $true
            SupportsDisable = $false
            SupportsEnable  = $false
            SupportsRemove  = $true
        }
    )

    $familyMappings = @(
        [PSCustomObject]@{
            Family          = 'IdentityAdmin'
            Description     = 'Privileged and identity-focused lures'
            ADDecoyTypes    = @('StaleAdminLure', 'DNSAdminUser')
            EntraDecoyTypes = @('EntraGuestUserDecoy')
        }
        [PSCustomObject]@{
            Family          = 'ServiceAuth'
            Description     = 'Service authentication and delegation lures'
            ADDecoyTypes    = @('KerberoastableUser', 'UnconstrainedDelegationComputer')
            EntraDecoyTypes = @('EntraServicePrincipalDecoy')
        }
        [PSCustomObject]@{
            Family          = 'AppPath'
            Description     = 'Application and attack-path lure chains'
            ADDecoyTypes    = @('ACLAttackPath')
            EntraDecoyTypes = @('EntraAppRegistrationDecoy')
        }
    )

    return [PSCustomObject]@{
        LifecycleActions = $lifecycleActions
        DecoyTypes       = $decoyTypes
        FamilyMappings   = $familyMappings
    }
}
