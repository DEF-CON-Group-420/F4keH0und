<#
.SYNOPSIS
    Validates COMMAND-REFERENCE coverage against currently exported module commands.

.DESCRIPTION
    Imports the local module manifest, collects all exported command names, and compares
    them to `## `<CommandName>`` headings in Docs/COMMAND-REFERENCE.md.

    The script fails when:
    - an exported command is missing from the command reference, or
    - the command reference contains command headings not exported by the module
      (unless -AllowExtraDocCommands is set).

.PARAMETER ModuleManifestPath
    Path to the module manifest (.psd1).

.PARAMETER CommandReferencePath
    Path to Docs/COMMAND-REFERENCE.md.

.PARAMETER AllowExtraDocCommands
    Allows extra command headings in docs that are not exported.

.EXAMPLE
    ./scripts/Test-CommandReferenceCoverage.ps1

.EXAMPLE
    ./scripts/Test-CommandReferenceCoverage.ps1 -AllowExtraDocCommands
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ModuleManifestPath = './F4keH0und.psd1',

    [Parameter()]
    [string]$CommandReferencePath = './Docs/COMMAND-REFERENCE.md',

    [Parameter()]
    [switch]$AllowExtraDocCommands
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $ModuleManifestPath -PathType Leaf)) {
    throw "Module manifest not found: $ModuleManifestPath"
}

if (-not (Test-Path -Path $CommandReferencePath -PathType Leaf)) {
    throw "Command reference file not found: $CommandReferencePath"
}

$module = Import-Module $ModuleManifestPath -Force -PassThru
$moduleCommands = @(
    Get-Command -Module $module.Name |
        Select-Object -ExpandProperty Name |
        Sort-Object -Unique
)

$referenceContent = Get-Content -Path $CommandReferencePath -Raw
$docCommandMatches = [regex]::Matches($referenceContent, '(?m)^## `([^`]+)`\s*$')
$docCommands = @(
    $docCommandMatches |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique
)

$missingInDocs = @($moduleCommands | Where-Object { $_ -notin $docCommands })
$extraInDocs = @($docCommands | Where-Object { $_ -notin $moduleCommands })

Write-Host "Module commands: $($moduleCommands.Count)"
Write-Host "Documented command sections: $($docCommands.Count)"

if ($missingInDocs.Count -gt 0) {
    Write-Error "Missing command sections in ${CommandReferencePath}:`n- $($missingInDocs -join "`n- ")"
}

if (-not $AllowExtraDocCommands -and $extraInDocs.Count -gt 0) {
    Write-Error "Undeclared command sections found in ${CommandReferencePath}:`n- $($extraInDocs -join "`n- ")"
}

if ($missingInDocs.Count -eq 0 -and ($AllowExtraDocCommands -or $extraInDocs.Count -eq 0)) {
    Write-Host 'Command reference coverage check passed.' -ForegroundColor Green
}
