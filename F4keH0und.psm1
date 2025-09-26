# The automatic variable $PSScriptRoot contains the full path to this script's directory.
# We use it to build the paths to our Public and Private folders, ensuring we always
# look inside the correct module directory.

$foldersToSearch = @(
    Join-Path -Path $PSScriptRoot -ChildPath "Public"
    Join-Path -Path $PSScriptRoot -ChildPath "Private"
)

# Find all .ps1 files ONLY within those specified folders.
Get-ChildItem -Path $foldersToSearch -Filter *.ps1 | ForEach-Object {
    try {
        . $_.FullName
    }
    catch {
        Write-Error "Failed to load script file: $($_.FullName). Error: $_"
    }
}