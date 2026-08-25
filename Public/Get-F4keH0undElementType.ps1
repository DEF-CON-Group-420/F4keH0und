<#
.SYNOPSIS
    Lists Windows artifact element types available for deployment.

.DESCRIPTION
    Reads the element type registry and returns available Windows-specific
    deception element families and capabilities used by `New/Update/Disable/
    Enable/Remove-F4keH0undElement`.

.PARAMETER Family
    Optional family filter (for example: ServiceLure, RpcBait, ApiHookBait,
    RuntimeArtifact).

.PARAMETER Platform
    Optional platform filter. Phase 3 currently supports `Windows` only.

.PARAMETER Detailed
    Includes descriptive metadata fields in output.

.EXAMPLE
    Get-F4keH0undElementType

.EXAMPLE
    Get-F4keH0undElementType -Family ApiHookBait -Detailed
#>
function Get-F4keH0undElementType {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [string]$Family,

        [Parameter()]
        [ValidateSet('Windows')]
        [string]$Platform = 'Windows',

        [Parameter()]
        [switch]$Detailed
    )

    $registry = Get-PrivateF4keH0undElementTypeRegistry
    $types = @($registry.Types)

    if (-not [string]::IsNullOrWhiteSpace($Family)) {
        $types = @($types | Where-Object { [string]$_.Family -eq $Family })
    }

    if (-not [string]::IsNullOrWhiteSpace($Platform)) {
        $types = @($types | Where-Object { @($_.Platforms) -contains $Platform })
    }

    if (-not $Detailed) {
        return @(
            $types | Select-Object TypeId, Family, @{ Name = 'Platform'; Expression = {
                if (@($_.Platforms).Count -gt 0) {
                    @($_.Platforms)[0]
                }
                else {
                    'Windows'
                }
            } }, @{ Name = 'Capabilities'; Expression = { (@($_.Capabilities) -join ',') } }, CostScore, DetectionScore
        )
    }

    return @($types)
}
