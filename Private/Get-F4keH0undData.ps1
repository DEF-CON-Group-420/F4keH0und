function Get-F4keH0undData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("AD", "Azure")]
        [string]$DataType
    )

    Write-Verbose "[$($MyInvocation.MyCommand)] - Starting data parsing for type '$DataType'."
    $parsedData = [PSCustomObject]@{ }

    if ($DataType -eq "AD") {
        # --- MODIFIED AD LOGIC ---
        # Instead of exact names, we look for files ending with the correct name.
        $requiredFileSuffixes = @{
            Users     = "_users.json";
            Groups    = "_groups.json";
            Computers = "_computers.json";
            Domains   = "_domains.json"
        }

        foreach ($key in $requiredFileSuffixes.Keys) {
            $filePattern = "*" + $requiredFileSuffixes[$key]
            Write-Verbose "[$($MyInvocation.MyCommand)] - Searching for file with pattern '$filePattern'."
            $foundFile = Get-ChildItem -Path $Path -Filter $filePattern | Select-Object -First 1

            if (-not $foundFile) {
                Write-Error "[$($MyInvocation.MyCommand)] - Required file not found: Could not find a file ending with '$($requiredFileSuffixes[$key])' in path '$Path'."
                return # Stop the function if a file is missing
            }

            $filePath = $foundFile.FullName
            Write-Verbose "[$($MyInvocation.MyCommand)] - Found and attempting to parse '$filePath'."

            try {
                $jsonData = Get-Content -Raw -Path $filePath | ConvertFrom-Json -ErrorAction Stop
                $parsedData | Add-Member -MemberType NoteProperty -Name $key -Value $jsonData
            }
            catch {
                Write-Error "[$($MyInvocation.MyCommand)] - Failed to parse JSON file '$filePath'. Error: $($_.Exception.Message)"
                return
            }
        }
    }
    elseif ($DataType -eq "Azure") {
        # --- COMPLETELY NEW AZURE LOGIC ---
        # Find the single JSON file in the directory.
        Write-Verbose "[$($MyInvocation.MyCommand)] - Searching for a single AzureHound JSON file in '$Path'."
        $azureFiles = Get-ChildItem -Path $Path -Filter "*.json"
        if ($azureFiles.Count -ne 1) {
            Write-Error "[$($MyInvocation.MyCommand)] - Expected to find exactly one JSON file for AzureHound data, but found $($azureFiles.Count)."
            return
        }

        $filePath = $azureFiles[0].FullName
        Write-Verbose "[$($MyInvocation.MyCommand)] - Found and attempting to parse '$filePath'."
        try {
            # Parse the single large JSON file
            $fullJsonData = Get-Content -Raw -Path $filePath | ConvertFrom-Json -ErrorAction Stop

            # Extract the data sections from inside the parsed file
            $parsedData | Add-Member -MemberType NoteProperty -Name "AzureUsers" -Value $fullJsonData.Users
            $parsedData | Add-Member -MemberType NoteProperty -Name "AzureGroups" -Value $fullJsonData.Groups
            $parsedData | Add-Member -MemberType NoteProperty -Name "ServicePrincipals" -Value $fullJsonData.ServicePrincipals
            $parsedData | Add-Member -MemberType NoteProperty -Name "AzureApps" -Value $fullJsonData.Apps
        }
        catch {
            Write-Error "[$($MyInvocation.MyCommand)] - Failed to parse AzureHound JSON file '$filePath'. Error: $($_.Exception.Message)"
            return
        }
    }

    Write-Verbose "[$($MyInvocation.MyCommand)] - Successfully parsed all required data."
    return $parsedData
}