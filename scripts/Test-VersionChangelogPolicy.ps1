<#
.SYNOPSIS
    Validates mandatory semantic version bump and changelog append policy.

.DESCRIPTION
    Enforces repository policy that every change set must:
    1) Bump `ModuleVersion` in `F4keH0und.psd1` using semantic-version progression.
    2) Append a new entry to `Docs/changelog.md` (append-only behavior).

    Intended for CI execution on push/pull_request by comparing two git refs.

.PARAMETER ModuleManifestPath
    Module manifest path containing `ModuleVersion`.

.PARAMETER ChangelogPath
    Changelog path that must be appended with new change notes.

.PARAMETER BaseRef
    Base git ref (for example merge-base SHA, push before SHA).

.PARAMETER HeadRef
    Head git ref (defaults to HEAD).

.EXAMPLE
    ./scripts/Test-VersionChangelogPolicy.ps1 -BaseRef abc123 -HeadRef def456
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ModuleManifestPath = './F4keH0und.psd1',

    [Parameter()]
    [string]$ChangelogPath = './Docs/changelog.md',

    [Parameter()]
    [string]$BaseRef,

    [Parameter()]
    [string]$HeadRef = 'HEAD'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-PolicyGitRef {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ref
    )

    $resolved = & git rev-parse --verify "$Ref^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($resolved -join ''))) {
        throw "Unable to resolve git ref '$Ref'."
    }

    return [string]($resolved | Select-Object -First 1).Trim()
}

function Convert-PolicyPathToGitPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $absolutePath = if ([System.IO.Path]::IsPathRooted($Path)) {
        (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    else {
        (Resolve-Path -LiteralPath (Join-Path -Path $RepositoryRoot -ChildPath $Path) -ErrorAction Stop).Path
    }

    $relativePath = [System.IO.Path]::GetRelativePath($RepositoryRoot, $absolutePath)
    return ($relativePath -replace '\\', '/')
}

function Get-PolicyManifestVersionFromText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestText,

        [Parameter(Mandatory = $true)]
        [string]$SourceLabel
    )

    $match = [regex]::Match($ManifestText, "(?m)^\s*ModuleVersion\s*=\s*'([^']+)'")
    if (-not $match.Success) {
        throw "Failed to parse ModuleVersion from $SourceLabel."
    }

    $rawVersion = [string]$match.Groups[1].Value
    $parsedVersion = $null
    if (-not [version]::TryParse($rawVersion, [ref]$parsedVersion)) {
        throw "Invalid ModuleVersion '$rawVersion' in $SourceLabel."
    }

    return [version]$parsedVersion
}

$repositoryRoot = (& git rev-parse --show-toplevel).Trim()
if ([string]::IsNullOrWhiteSpace($repositoryRoot)) {
    throw 'Unable to determine repository root.'
}

if ([string]::IsNullOrWhiteSpace($BaseRef)) {
    $inferredBase = & git rev-parse 'HEAD^' 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($inferredBase -join ''))) {
        Write-Warning 'No BaseRef provided and unable to infer HEAD^. Skipping policy check.'
        exit 0
    }

    $BaseRef = [string]($inferredBase | Select-Object -First 1).Trim()
}

if ($BaseRef -match '^0+$') {
    Write-Warning "BaseRef '$BaseRef' is all-zero (initial push context). Skipping policy check."
    exit 0
}

$resolvedBaseRef = Resolve-PolicyGitRef -Ref $BaseRef
$resolvedHeadRef = Resolve-PolicyGitRef -Ref $HeadRef

$changedFiles = @(& git diff --name-only "$resolvedBaseRef..$resolvedHeadRef" | ForEach-Object { [string]$_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($changedFiles.Count -eq 0) {
    Write-Host 'No file changes detected between refs; policy check passed.' -ForegroundColor Green
    exit 0
}

$manifestGitPath = Convert-PolicyPathToGitPath -Path $ModuleManifestPath -RepositoryRoot $repositoryRoot
$changelogGitPath = Convert-PolicyPathToGitPath -Path $ChangelogPath -RepositoryRoot $repositoryRoot

if (@($changedFiles) -notcontains $manifestGitPath) {
    throw "Policy violation: '$manifestGitPath' must be updated for every change set."
}

if (@($changedFiles) -notcontains $changelogGitPath) {
    throw "Policy violation: '$changelogGitPath' must be appended for every change set."
}

$oldManifestText = (& git show "$resolvedBaseRef`:$manifestGitPath" 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read '$manifestGitPath' from base ref '$resolvedBaseRef'."
}

$newManifestText = (& git show "$resolvedHeadRef`:$manifestGitPath" 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read '$manifestGitPath' from head ref '$resolvedHeadRef'."
}

$oldVersion = Get-PolicyManifestVersionFromText -ManifestText $oldManifestText -SourceLabel "base ref '$resolvedBaseRef'"
$newVersion = Get-PolicyManifestVersionFromText -ManifestText $newManifestText -SourceLabel "head ref '$resolvedHeadRef'"

if ($newVersion -le $oldVersion) {
    throw "Policy violation: ModuleVersion must increase. Base=$oldVersion, Head=$newVersion."
}

$bumpType = $null
if ($newVersion.Major -gt $oldVersion.Major) {
    $bumpType = 'major'
    if ($newVersion.Minor -ne 0 -or $newVersion.Build -ne 0) {
        throw "Policy violation: major bump must reset minor/patch to 0. Head=$newVersion."
    }
}
elseif ($newVersion.Major -eq $oldVersion.Major -and $newVersion.Minor -gt $oldVersion.Minor) {
    $bumpType = 'minor'
    if ($newVersion.Build -ne 0) {
        throw "Policy violation: minor bump must reset patch to 0. Head=$newVersion."
    }
}
elseif ($newVersion.Major -eq $oldVersion.Major -and $newVersion.Minor -eq $oldVersion.Minor -and $newVersion.Build -gt $oldVersion.Build) {
    $bumpType = 'patch'
}
else {
    throw "Policy violation: invalid semantic version progression. Base=$oldVersion, Head=$newVersion."
}

$oldChangelogContent = $null
$oldChangelogExists = $true
$oldChangelogRaw = & git show "$resolvedBaseRef`:$changelogGitPath" 2>$null
if ($LASTEXITCODE -ne 0) {
    $oldChangelogExists = $false
    $oldChangelogContent = ''
}
else {
    $oldChangelogContent = (($oldChangelogRaw | ForEach-Object { [string]$_ }) -join "`n")
}

$newChangelogRaw = & git show "$resolvedHeadRef`:$changelogGitPath" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Policy violation: changelog file '$changelogGitPath' is missing in head ref '$resolvedHeadRef'."
}

$newChangelogContent = (($newChangelogRaw | ForEach-Object { [string]$_ }) -join "`n")

if ($oldChangelogExists) {
    if ($newChangelogContent.Length -le $oldChangelogContent.Length) {
        throw "Policy violation: '$changelogGitPath' must append new content."
    }

    if (-not $newChangelogContent.StartsWith($oldChangelogContent, [System.StringComparison]::Ordinal)) {
        throw "Policy violation: '$changelogGitPath' must be append-only (existing content changed)."
    }

    $appendedContent = $newChangelogContent.Substring($oldChangelogContent.Length)
    if ([string]::IsNullOrWhiteSpace($appendedContent)) {
        throw "Policy violation: '$changelogGitPath' append content is empty."
    }
}
else {
    if ([string]::IsNullOrWhiteSpace($newChangelogContent)) {
        throw "Policy violation: '$changelogGitPath' must contain at least one entry."
    }
}

$newVersionText = "{0}.{1}.{2}" -f $newVersion.Major, $newVersion.Minor, $newVersion.Build
if ($newChangelogContent -notmatch [regex]::Escape($newVersionText)) {
    throw "Policy violation: '$changelogGitPath' must include the new version '$newVersionText'."
}

Write-Host "Version/changelog policy check passed. BumpType=$bumpType Base=$oldVersion Head=$newVersion" -ForegroundColor Green
