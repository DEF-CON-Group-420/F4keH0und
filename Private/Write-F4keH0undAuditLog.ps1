function Write-F4keH0undAuditLog {
    <#
    .SYNOPSIS
        Writes a structured JSON audit log entry for F4keH0und recycling operations.

    .DESCRIPTION
        Records detailed telemetry for every object recycling operation performed by F4keH0und.
        Each entry captures a timestamp, the operation type, the original state of the AD or
        Entra ID object before modification, and a summary of every change made.

        Log entries are appended as newline-delimited JSON (NDJSON) so the file can be
        streamed into any log-aggregation pipeline (SIEM, Splunk, Elastic) or imported
        directly into a PostgreSQL table with COPY ... (FORMAT json).

        PostgreSQL-compatible schema (for future F4keH0und NG migration):
        CREATE TABLE f4keh0und_audit (
            id            BIGSERIAL PRIMARY KEY,
            timestamp     TIMESTAMPTZ NOT NULL,
            operation     TEXT        NOT NULL,
            object_guid   TEXT,
            source        TEXT        NOT NULL DEFAULT 'AD',
            original_state JSONB,
            modifications  JSONB,
            operator      TEXT,
            host          TEXT
        );

    .PARAMETER AuditLogPath
        Full path to the JSON audit log file. The file is created if it does not exist.
        The parent directory must already exist. If omitted, nothing is written.

    .PARAMETER Operation
        The operation being performed (e.g. RecycleUser, RecycleComputer, RecycleGroup,
        RecycleEntraPrincipal).

    .PARAMETER ObjectGuid
        The objectGUID (or Entra ID object ID) of the target object.

    .PARAMETER Source
        The identity source: 'AD' (default) or 'Entra'.

    .PARAMETER OriginalState
        A hashtable describing the object's state before modification. Recommended keys:
        samAccountName, rid, whenCreated, enabled, lastLogon, description, spns.

    .PARAMETER Modifications
        A hashtable describing every attribute that was changed and how.
        Example: @{ description = "Changed to: Production SQL Service Account";
                    servicePrincipalName = "Added: MSSQLSvc/prod-sql.domain.local:1433" }

    .PARAMETER Operator
        Optional. The identity that performed the operation (defaults to current user).

    .EXAMPLE
        Write-F4keH0undAuditLog -AuditLogPath "C:\Logs\f4keh0und_audit.json" `
            -Operation RecycleUser `
            -ObjectGuid $user.ObjectGUID `
            -OriginalState @{ samAccountName = $user.SamAccountName; rid = 1523; enabled = $false } `
            -Modifications @{ description = "Changed to: Production SQL Service Account" }

    .NOTES
        Each invocation appends exactly one JSON line to the log file (NDJSON format).
        The file is safe to tail in real time and to import into PostgreSQL with:
            -- Using psql \copy with jq pre-processing (recommended for NDJSON):
            -- jq -R '. | @csv' f4keh0und_audit.json | psql -c "\copy f4keh0und_audit FROM STDIN (FORMAT csv)"
            --
            -- Or via a foreign data wrapper / json_populate_record for each line:
            INSERT INTO f4keh0und_audit (timestamp, operation, object_guid, source,
                                         original_state, modifications, operator, host)
            SELECT (value->>'timestamp')::TIMESTAMPTZ,
                   value->>'operation',
                   value->>'objectGuid',
                   value->>'source',
                   (value->'originalState')::JSONB,
                   (value->'modifications')::JSONB,
                   value->>'operator',
                   value->>'host'
            FROM   jsonb_each(pg_read_file('/path/to/f4keh0und_audit.json')::JSONB);
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AuditLogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet('RecycleUser', 'RecycleComputer', 'RecycleGroup', 'RecycleEntraPrincipal')]
        [string]$Operation,

        [Parameter()]
        [string]$ObjectGuid,

        [Parameter()]
        [ValidateSet('AD', 'Entra')]
        [string]$Source = 'AD',

        [Parameter()]
        [hashtable]$OriginalState = @{},

        [Parameter()]
        [hashtable]$Modifications = @{},

        [Parameter()]
        [string]$Operator
    )

    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        return
    }

    $entry = [ordered]@{
        timestamp     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        operation     = $Operation
        objectGuid    = $ObjectGuid
        source        = $Source
        originalState = $OriginalState
        modifications = $Modifications
        operator      = if ($PSBoundParameters.ContainsKey('Operator')) {
            $Operator
        } else {
            try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
            catch { $env:USERNAME }
        }
        host          = $env:COMPUTERNAME
    }

    $line = $entry | ConvertTo-Json -Compress -Depth 5

    try {
        Add-Content -Path $AuditLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "[$($MyInvocation.MyCommand)] - Audit entry written to '$AuditLogPath' (operation: $Operation, objectGuid: $ObjectGuid)."
    }
    catch {
        Write-Warning "[$($MyInvocation.MyCommand)] - Failed to write audit log entry to '$AuditLogPath'. Error: $($_.Exception.Message)"
    }
}
