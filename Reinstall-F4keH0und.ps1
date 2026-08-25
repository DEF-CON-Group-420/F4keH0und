<#
.SYNOPSIS
    Cleanly removes every cached/installed copy of F4keH0und and reinstalls
    the freshly-pulled source from a local git clone.

.DESCRIPTION
    Users who install F4keH0und by copying the module to a path in
    $env:PSModulePath and later run `git pull`
    in their local clone frequently hit errors like:

        New-F4keH0undDecoy: A parameter cannot be found that matches
        parameter name 'PreferRecycling'.

    This happens because PowerShell loads the previously installed copy from
    $env:PSModulePath (and/or the ModuleAnalysisCache) rather than the
    freshly-pulled source tree. This script:

      1. Unloads any in-memory copy of the module from the current session.
      2. Wipes every installed copy from every directory in $env:PSModulePath.
      3. Clears the PowerShell ModuleAnalysisCache across common Windows/macOS/Linux paths.
      4. Optionally pulls the latest source via `git fetch --all` and
         `git reset --hard origin/<Branch>` (requires -PullLatest).
      5. Reinstalls the fresh copy to your user module path in $env:PSModulePath.
      6. Imports the module and verifies the -PreferRecycling parameter is present.

.PARAMETER SourcePath
    Path to the local git clone of F4keH0und.
    Default: current repository root (script directory)

.PARAMETER PullLatest
    When set, runs `git fetch --all` and `git reset --hard origin/<Branch>`
    inside $SourcePath before reinstalling.

.PARAMETER Branch
    Branch to reset to when -PullLatest is set.
    Default: main

.EXAMPLE
    .\Reinstall-F4keH0und.ps1

    Reinstalls F4keH0und from the default source path without pulling from git.

.EXAMPLE
    .\Reinstall-F4keH0und.ps1 -PullLatest

    Pulls the latest commits from origin/main, then reinstalls.

.EXAMPLE
    .\Reinstall-F4keH0und.ps1 -SourcePath 'C:\repos\F4keH0und' -PullLatest -Branch dev

    Pulls origin/dev, then reinstalls from a custom source path.

.EXAMPLE
    ./Reinstall-F4keH0und.ps1 -SourcePath "$HOME/src/F4keH0und" -PullLatest

    Pulls latest code and reinstalls from a macOS/Linux clone path.
#>
[CmdletBinding()]
param(
    [string]$SourcePath = $PSScriptRoot,
    [switch]$PullLatest,
    [string]$Branch = 'main'
)

$ErrorActionPreference = 'Stop'
$ModuleName = 'F4keH0und'

# ------------------------------------------------------------------
# Validate source path
# ------------------------------------------------------------------
if (-not (Test-Path $SourcePath)) {
    throw "SourcePath '$SourcePath' does not exist. Please specify a valid path to your F4keH0und git clone."
}

# ------------------------------------------------------------------
# Step 1 — Unload in-memory copies from this session
# ------------------------------------------------------------------
Write-Host "[1/6] Unloading $ModuleName from current session..." -ForegroundColor Cyan
Get-Module $ModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------------
# Step 2 — Wipe every installed copy across $env:PSModulePath
# ------------------------------------------------------------------
Write-Host "[2/6] Searching all module paths for installed copies..." -ForegroundColor Cyan
$modulePaths = $env:PSModulePath -split [IO.Path]::PathSeparator | Where-Object { $_ }
foreach ($p in $modulePaths) {
    $target = Join-Path $p $ModuleName
    if (Test-Path $target) {
        Write-Host "      Removing $target" -ForegroundColor Yellow
        try {
            Remove-Item -Path $target -Recurse -Force -ErrorAction Stop
            Write-Host "      Removed  $target" -ForegroundColor Green
        }
        catch {
            Write-Warning "      Could not remove '$target': $($_.Exception.Message)"
        }
    }
}

# ------------------------------------------------------------------
# Step 3 — Clear PowerShell ModuleAnalysisCache
# ------------------------------------------------------------------
Write-Host "[3/6] Clearing ModuleAnalysisCache..." -ForegroundColor Cyan

$cacheCandidates = [System.Collections.Generic.List[string]]::new()
if ($env:LOCALAPPDATA) {
    $cacheCandidates.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\PowerShell\ModuleAnalysisCache'))
    $cacheCandidates.Add((Join-Path $env:LOCALAPPDATA 'PowerShell\ModuleAnalysisCache'))
}
if ($env:XDG_CACHE_HOME) {
    $cacheCandidates.Add((Join-Path $env:XDG_CACHE_HOME 'powershell/ModuleAnalysisCache'))
}

$homePath = [Environment]::GetFolderPath('UserProfile')
if ($homePath) {
    $cacheCandidates.Add((Join-Path $homePath '.cache/powershell/ModuleAnalysisCache'))
    $cacheCandidates.Add((Join-Path $homePath '.local/share/powershell/ModuleAnalysisCache'))
}

$cacheCandidates | Select-Object -Unique | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item $_ -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------
# Step 4 — Optional git pull
# ------------------------------------------------------------------
if ($PullLatest) {
    Write-Host "[4/6] Validating git is available..." -ForegroundColor Cyan
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "'git' was not found on PATH. Install Git or add it to your PATH before using -PullLatest."
    }
    Write-Host "[4/6] Pulling latest source (origin/$Branch) in $SourcePath..." -ForegroundColor Cyan
    Push-Location $SourcePath
    git fetch --all
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        throw "git fetch --all failed with exit code $LASTEXITCODE."
    }
    git reset --hard "origin/$Branch"
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        throw "git reset --hard origin/$Branch failed with exit code $LASTEXITCODE."
    }
    Pop-Location
} else {
    Write-Host "[4/6] Skipping git pull (use -PullLatest to pull origin/$Branch first)." -ForegroundColor DarkGray
}

# ------------------------------------------------------------------
# Step 5 — Reinstall fresh copy
# ------------------------------------------------------------------
$homePath = [Environment]::GetFolderPath('UserProfile')
$destRoot = $modulePaths | Where-Object { $homePath -and $_ -like "$homePath*" } | Select-Object -First 1
if (-not $destRoot) {
    $destRoot = $modulePaths | Select-Object -First 1
}
if (-not $destRoot) {
    throw "No PowerShell module destination was found in `$env:PSModulePath."
}

$dest = Join-Path $destRoot $ModuleName

Write-Host "[5/6] Installing fresh copy to $dest..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $destRoot | Out-Null
if (Test-Path $dest) {
    Remove-Item -Path $dest -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $SourcePath '*') -Destination $dest -Recurse -Force

# ------------------------------------------------------------------
# Step 6 — Import and verify
# ------------------------------------------------------------------
Write-Host "[6/6] Importing $ModuleName and verifying..." -ForegroundColor Cyan
Import-Module $ModuleName -Force
Get-Module $ModuleName | Format-Table Name, Version, Path

Write-Host "Verifying -PreferRecycling parameter on New-F4keH0undDecoy..." -ForegroundColor Cyan
if ((Get-Command New-F4keH0undDecoy).Parameters.ContainsKey('PreferRecycling')) {
    Write-Host "  OK — -PreferRecycling is available." -ForegroundColor Green
} else {
    Write-Warning "  -PreferRecycling NOT found. Confirm that `$SourcePath` is on the latest commit of $Branch."
}
