function Get-PrivateF4keH0undRolloutProfileValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()]
        [object]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Property,

        [Parameter()]
        [object]$DefaultValue
    )

    if ($null -eq $Source) {
        return $DefaultValue
    }

    if ($Source -is [System.Collections.IDictionary]) {
        if ($Source.Contains($Property)) {
            return $Source[$Property]
        }

        return $DefaultValue
    }

    if ($Source.PSObject.Properties.Name -contains $Property) {
        return $Source.$Property
    }

    return $DefaultValue
}

function Get-PrivateF4keH0undRolloutProfile {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter()]
        [ValidateSet('Lab', 'Pilot', 'Production')]
        [string]$Name
    )

    $defaults = (Get-F4keH0undDefaultConfig).RolloutProfiles
    $configuredProfiles = Get-F4keH0undConfig -Section 'RolloutProfiles'
    if ($null -eq $configuredProfiles) {
        $configuredProfiles = $defaults
    }

    $defaultProfileName = [string](Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfiles -Property 'DefaultProfile' -DefaultValue 'Pilot')
    if ([string]::IsNullOrWhiteSpace($defaultProfileName) -or $defaultProfileName -notin @('Lab', 'Pilot', 'Production')) {
        $defaultProfileName = 'Pilot'
    }

    $resolvedName = if ($PSBoundParameters.ContainsKey('Name')) {
        [string]$Name
    }
    else {
        $defaultProfileName
    }

    if ($resolvedName -notin @('Lab', 'Pilot', 'Production')) {
        $resolvedName = 'Pilot'
    }

    $defaultProfilesTable = Get-PrivateF4keH0undRolloutProfileValue -Source $defaults -Property 'Profiles' -DefaultValue $null
    $configuredProfilesTable = Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfiles -Property 'Profiles' -DefaultValue $null

    $defaultProfile = Get-PrivateF4keH0undRolloutProfileValue -Source $defaultProfilesTable -Property $resolvedName -DefaultValue $null
    $configuredProfile = Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfilesTable -Property $resolvedName -DefaultValue $null

    $windowsThrottle = [int](Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfile -Property 'WindowsThrottleLimit' -DefaultValue (Get-PrivateF4keH0undRolloutProfileValue -Source $defaultProfile -Property 'WindowsThrottleLimit' -DefaultValue 10))
    if ($windowsThrottle -lt 1) {
        $windowsThrottle = 1
    }

    $maxEntraDeployments = [int](Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfile -Property 'MaxEntraDeploymentsPerRun' -DefaultValue (Get-PrivateF4keH0undRolloutProfileValue -Source $defaultProfile -Property 'MaxEntraDeploymentsPerRun' -DefaultValue 5))
    if ($maxEntraDeployments -lt 1) {
        $maxEntraDeployments = 1
    }

    $defaultWhatIf = [bool](Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfile -Property 'DefaultWhatIf' -DefaultValue (Get-PrivateF4keH0undRolloutProfileValue -Source $defaultProfile -Property 'DefaultWhatIf' -DefaultValue $false))
    $allowHighPriv = [bool](Get-PrivateF4keH0undRolloutProfileValue -Source $configuredProfile -Property 'AllowHighPrivilegeRoleAssignment' -DefaultValue (Get-PrivateF4keH0undRolloutProfileValue -Source $defaultProfile -Property 'AllowHighPrivilegeRoleAssignment' -DefaultValue $false))

    return [PSCustomObject]@{
        Name                             = $resolvedName
        DefaultProfile                   = $defaultProfileName
        DefaultWhatIf                    = $defaultWhatIf
        WindowsThrottleLimit             = $windowsThrottle
        MaxEntraDeploymentsPerRun        = $maxEntraDeployments
        AllowHighPrivilegeRoleAssignment = $allowHighPriv
    }
}
