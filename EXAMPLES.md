# F4keH0und — Deployment Examples

This file contains annotated, real-world deployment scenarios. Each example is self-contained and can be run directly after importing the module.

---

## Contents

1. [First-Time Deployment](#1-first-time-deployment)
2. [Recycling-Only Mode](#2-recycling-only-mode)
3. [Multi-Domain Deployment (Bastion Host)](#3-multi-domain-deployment-bastion-host)
4. [Production Deployment with VIP Exclusions](#4-production-deployment-with-vip-exclusions)
5. [Kerberoasting Detection Setup](#5-kerberoasting-detection-setup)
6. [ACL Attack Path Monitoring](#6-acl-attack-path-monitoring)
7. [Inspecting Recyclable Candidates Before Deployment](#7-inspecting-recyclable-candidates-before-deployment)
8. [Configuration Management Workflow](#8-configuration-management-workflow)
9. [Permission Testing with WhatIf](#9-permission-testing-with-whatif)
10. [Entra ID Hybrid Deployment](#10-entra-id-hybrid-deployment)
11. [Post-Deployment Verification](#11-post-deployment-verification)
12. [Bulk Cleanup](#12-bulk-cleanup)

---

## 1. First-Time Deployment

A complete end-to-end walkthrough for a first deployment on a domain-joined machine.

```powershell
# Step 1: Import the module
Import-Module F4keH0und -Force

# Step 2: Validate your configuration before touching the domain
Test-F4keH0undConfig -Verbose

# Step 3: Analyze BloodHound data (read-only — safe to run from any machine)
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\BH_Data\" `
    -PreferRecycling `
    -Verbose

# Step 4: Review what was found
$opportunities | Format-Table DecoyType, Rank, Source, Identity, StalenessScore -AutoSize

# Step 5: Dry run — see exactly what would happen with no AD writes
New-F4keH0undDecoy -BloodHoundPath "C:\BH_Data\" -Execute -PreferRecycling -WhatIf

# Step 6: Deploy for real
New-F4keH0undDecoy -BloodHoundPath "C:\BH_Data\" -Execute -PreferRecycling
```

**Expected output from Step 4:**
```
DecoyType                    Rank     Source   Identity                               StalenessScore
---------                    ----     ------   --------                               --------------
StaleAdminLure               Critical Recycle  CN=j.harris,OU=Legacy,DC=corp,DC=local 91
KerberoastableUser           High     Recycle  CN=m.jones,OU=Old,DC=corp,DC=local     78
UnconstrainedDelegationComp  High     Recycle  CN=WS-OLD-07,OU=Legacy,DC=corp,DC=lo   65
DNSAdminUser                 Critical Recycle  CN=t.brown,OU=Disabled,DC=corp,DC=loc  82
ACLAttackPath                High     Recycle  CN=svc_backup,OU=Legacy,DC=corp,DC=lo  74
```

---

## 2. Recycling-Only Mode

Enforce a strict "zero new objects" policy. If the domain has no suitable stale objects, the command returns an empty array rather than creating anything.

```powershell
# Strict mode — only recycle, never create
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\BH_Data\" `
    -RecyclingOnly `
    -Verbose

if ($opportunities.Count -eq 0) {
    Write-Warning "No recyclable objects found. Widen the age window or lower MinimumObjectAgeDays in config.json."
} else {
    Write-Host "Found $($opportunities.Count) recyclable opportunities."
    New-F4keH0undDecoy -BloodHoundPath "C:\BH_Data\" -Execute -RecyclingOnly
}
```

**When to use this mode:**
- Security policies that prohibit creating any new AD objects.
- Environments where naming convention violations must be avoided.
- Audits where you need to prove zero new objects were created.

---

## 3. Multi-Domain Deployment (Bastion Host)

Run F4keH0und from a privileged bastion host against a target domain without joining it. The `-Server` and `-Credential` parameters handle all cross-domain authentication.

```powershell
# Collect credentials for the target domain
$targetCred = Get-Credential -Message "Enter credentials for CORP\DomainAdmin"
$targetDC   = "DC01.corp.contoso.local"

# Analyze
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\BH_Data\" `
    -PreferRecycling `
    -Server $targetDC `
    -Credential $targetCred `
    -Verbose

# Dry run
New-F4keH0undDecoy `
    -BloodHoundPath "C:\BH_Data\" `
    -Execute `
    -PreferRecycling `
    -Server $targetDC `
    -Credential $targetCred `
    -WhatIf

# Deploy
New-F4keH0undDecoy `
    -BloodHoundPath "C:\BH_Data\" `
    -Execute `
    -PreferRecycling `
    -Server $targetDC `
    -Credential $targetCred
```

**Note:** TCP 9389 (AD Web Services) must be reachable from the bastion to the target DC.

---

## 4. Production Deployment with VIP Exclusions

In production environments, certain OUs must never be touched. Pass `-ExcludeOUs` at runtime to override or supplement the patterns in `config.json`.

```powershell
# Define OUs that must never be recycled
$protectedOUs = @(
    "OU=VIP,DC=corp,DC=contoso,DC=local",
    "OU=Executives,DC=corp,DC=contoso,DC=local",
    "OU=Finance,DC=corp,DC=contoso,DC=local",
    "OU=PCI,DC=corp,DC=contoso,DC=local"
)

$cred = Get-Credential -Message "Domain Admin credentials"
$dc   = "DC01.corp.contoso.local"

# Analysis with OU exclusions
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\BH_Data\" `
    -PreferRecycling `
    -ExcludeOUs $protectedOUs `
    -Server $dc `
    -Credential $cred `
    -Verbose

# Show only Critical-ranked opportunities for initial review
$critical = $opportunities | Where-Object { $_.Rank -eq 'Critical' }
Write-Host "Critical opportunities: $($critical.Count)"
$critical | Format-Table DecoyType, Identity, StalenessScore -AutoSize

# Deploy all opportunities
New-F4keH0undDecoy `
    -BloodHoundPath "C:\BH_Data\" `
    -Execute `
    -PreferRecycling `
    -ExcludeOUs $protectedOUs `
    -Server $dc `
    -Credential $cred
```

---

## 5. Kerberoasting Detection Setup

Deploy KerberoastableUser decoys specifically to detect Kerberoasting attacks. The recycled user gets a tempting SPN that any Kerberoasting tool will request a TGS for.

```powershell
# Analyze — look specifically for Kerberoastable opportunities
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\BH_Data\" `
    -PreferRecycling `
    -Verbose

$kerberoastTargets = $opportunities | Where-Object { $_.DecoyType -eq 'KerberoastableUser' }
Write-Host "Kerberoastable decoy candidates: $($kerberoastTargets.Count)"
$kerberoastTargets | Format-Table Identity, StalenessScore, SuggestedSPN -AutoSize

# Deploy Kerberoastable decoys
New-F4keH0undDecoy `
    -BloodHoundPath "C:\BH_Data\" `
    -Execute `
    -PreferRecycling
```

**What happens after deployment:**
The recycled user gets an SPN like `MSSQLSvc/prod-sql01.corp.local:1433`. When an attacker runs:
```
Rubeus.exe kerberoast /nowrap
```
or
```
python3 GetUserSPNs.py corp.local/user:pass -dc-ip 10.0.0.1 -request
```
...a TGS request for the decoy SPN is captured in your SIEM, identifying the attacker's machine.

**Recommended SIEM alert:**
```
EventID 4769 (Kerberos Service Ticket Requested) WHERE ServiceName = "MSSQLSvc/prod-sql01.corp.local"
```

---

## 6. ACL Attack Path Monitoring

Deploy a synthetic multi-hop ACL attack path using recycled objects. BloodHound will discover this path and attackers following it will interact with monitored decoys at every step.

```powershell
# Step 1: Deploy base decoys first
$cred = Get-Credential
New-F4keH0undDecoy -BloodHoundPath "C:\BH_Data\" -Execute -PreferRecycling -Credential $cred -Server "DC01.corp.local"

# Step 2: Read the deployment report to find deployed decoy identities
$report = Import-Csv ".\reports\F4keH0und_Report_*.csv" | Select-Object -Last 1

# Step 3: Wire up the ACL attack path between deployed decoys
# This creates: decoy_user -[GenericWrite]-> decoy_group -[AddMember]-> domain_admin_group
Add-F4keH0undRelationship `
    -SourceIdentity "CN=j.harris,OU=Legacy,DC=corp,DC=local" `
    -TargetIdentity "CN=IT-Helpdesk,OU=Groups,DC=corp,DC=local" `
    -RelationshipType "GenericWrite" `
    -Server "DC01.corp.local" `
    -Credential $cred

# Step 4: Verify the path appears in BloodHound after next collection run
Write-Host "Re-run SharpHound to pick up the new ACL relationships."
Write-Host "Then search BloodHound: MATCH p=shortestPath((n)-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p"
```

**What to monitor:**
- Any `Set-ACL` or `WriteDacl` events on the decoy objects.
- BloodHound path traversal queries that reference decoy accounts.
- Authentication attempts (Event ID 4624, 4625) from the decoy accounts.

---

## 7. Inspecting Recyclable Candidates Before Deployment

Use the recycling engine directly to audit what objects are eligible before committing to any deployment.

```powershell
# List all recyclable user candidates with scoring
$userCandidates = Find-F4keH0undRecyclableObject `
    -Type User `
    -MinimumAgeDays 180 `
    -MaximumAgeDays 3650 `
    -Verbose

$userCandidates |
    Select-Object SamAccountName, StalenessScore, DaysSinceCreation, RecommendedDecoyType, DistinguishedName |
    Sort-Object StalenessScore -Descending |
    Format-Table -AutoSize

# Same for computers
$compCandidates = Find-F4keH0undRecyclableObject -Type Computer -MinimumAgeDays 90

# Same for groups
$groupCandidates = Find-F4keH0undRecyclableObject -Type Group -MinimumAgeDays 365

Write-Host "Summary:"
Write-Host "  Recyclable users:     $($userCandidates.Count)"
Write-Host "  Recyclable computers: $($compCandidates.Count)"
Write-Host "  Recyclable groups:    $($groupCandidates.Count)"
```

**StalenessScore interpretation:**

| Score | Suitability |
|-------|-------------|
| 80–100 | Excellent — highly stale, isolated, ideal for recycling |
| 60–79 | Good — suitable for most decoy types |
| 40–59 | Moderate — review manually before recycling |
| 0–39 | Poor — likely too recently active; skip |

---

## 8. Configuration Management Workflow

Manage and validate F4keH0und configuration before and after changes.

```powershell
# Read the current configuration
$config = Get-F4keH0undConfig
$config | ConvertTo-Json -Depth 5

# Read a specific section
$recyclingPrefs = Get-F4keH0undConfig -Section RecyclingPreferences
Write-Host "PreferRecycling: $($recyclingPrefs.PreferRecycling)"
Write-Host "MinimumObjectAgeDays: $($recyclingPrefs.MinimumObjectAgeDays)"

$safetyFilters = Get-F4keH0undConfig -Section SafetyFilters
Write-Host "ExcludedOUs: $($safetyFilters.ExcludedOUs -join ', ')"
Write-Host "ProtectedUserPatterns: $($safetyFilters.ProtectedUserPatterns.Count) patterns"

# Validate the full configuration
$validationResult = Test-F4keH0undConfig -Verbose
if ($validationResult) {
    Write-Host "Configuration is valid." -ForegroundColor Green
} else {
    Write-Warning "Configuration validation failed — check the verbose output above."
}
```

**Typical config customization for a strict environment:**
```json
{
  "RecyclingPreferences": {
    "PreferRecycling": true,
    "RecyclingOnly": true,
    "MinimumObjectAgeDays": 365
  },
  "SafetyFilters": {
    "ExcludedOUs": [
      "OU=VIP,DC=corp,DC=contoso,DC=local",
      "OU=Executives,DC=corp,DC=contoso,DC=local",
      "OU=Finance,DC=corp,DC=contoso,DC=local"
    ],
    "ProtectedUserPatterns": [
      "^Administrator$", "^krbtgt$", "^Guest$",
      "^MSOL_", "^AAD_", "^admin", "^svc_prod"
    ],
    "RequireDisabledAccounts": true,
    "RequireEmptyGroups": true
  }
}
```

---

## 9. Permission Testing with WhatIf

Before a production deployment, verify that your credentials have the required permissions across all decoy types without making any changes.

```powershell
$cred = Get-Credential -Message "Test with Domain Admin credentials"
$dc   = "DC01.corp.contoso.local"

# Full dry run across all decoy types
Write-Host "Running permission test (WhatIf mode)..." -ForegroundColor Cyan

New-F4keH0undDecoy `
    -BloodHoundPath "C:\BH_Data\" `
    -Execute `
    -PreferRecycling `
    -Server $dc `
    -Credential $cred `
    -WhatIf `
    -Verbose

Write-Host "If no 'Access Denied' errors appeared above, credentials are sufficient." -ForegroundColor Green
```

**What WhatIf tests:**
- Read access to target AD objects.
- Write access simulation for `Set-ADUser`, `Set-ADComputer`, `Set-ADGroup`.
- Group membership modification simulation.
- ACL write simulation (for ACLAttackPath decoys).

**Minimum required permissions for deployment:**
- `Create Child Objects` on target OUs (only for new-object creation, not recycling).
- `Write All Properties` on the specific objects to be recycled.
- `Add/Remove Group Member` on target groups (DnsAdmins, etc.).

---

## 10. Entra ID Hybrid Deployment

Deploy decoys in a hybrid AD + Entra ID environment using both SharpHound and AzureHound data.

```powershell
# Step 1: Analyze on-premises AD data
$adOpportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath "C:\SharpHound_Data\" `
    -PreferRecycling `
    -Verbose

# Step 2: Analyze Entra ID data
$entraOpportunities = Find-F4keH0undOpportunity `
    -AzureHoundPath "C:\AzureHound_Data\" `
    -Verbose

# Step 3: Review all opportunities
Write-Host "On-premises opportunities: $($adOpportunities.Count)"
Write-Host "Entra ID opportunities:    $($entraOpportunities.Count)"

$adOpportunities + $entraOpportunities |
    Sort-Object Rank |
    Format-Table DecoyType, Rank, Source, Identity -AutoSize

# Step 4: Deploy AD decoys (recycling-first)
New-F4keH0undDecoy `
    -BloodHoundPath "C:\SharpHound_Data\" `
    -Execute `
    -PreferRecycling

# Step 5: Deploy Entra ID decoys
New-F4keH0undDecoy `
    -AzureHoundPath "C:\AzureHound_Data\" `
    -Execute
```

**Entra ID decoy type — PrivilegedEntraSP:**

The `PrivilegedEntraSP` decoy creates a Service Principal with a high-privilege role (e.g., Global Reader, Security Reader) that appears enticing in AzureHound graphs. Any OAuth token request or role enumeration against this SP is flagged.

---

## 11. Post-Deployment Verification

After deployment, verify that decoys were created/recycled correctly and that the handover report is complete.

```powershell
# Read the latest deployment report
$reportPath = ".\reports"
$latestReport = Get-ChildItem $reportPath -Filter "*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($latestReport) {
    $deployedDecoys = Import-Csv $latestReport.FullName
    Write-Host "Deployed $($deployedDecoys.Count) decoys in last run:"
    $deployedDecoys | Format-Table DecoyType, Identity, Source, DeployedAt -AutoSize
} else {
    Write-Warning "No deployment report found in $reportPath"
}

# Verify a specific decoy is still in place
$cred = Get-Credential
$dc   = "DC01.corp.local"

foreach ($decoy in $deployedDecoys | Where-Object { $_.Source -eq 'Recycle' }) {
    $adUser = Get-ADUser -Identity $decoy.SamAccountName -Server $dc -Credential $cred -ErrorAction SilentlyContinue
    if ($adUser) {
        Write-Host "OK: $($decoy.SamAccountName) exists" -ForegroundColor Green
    } else {
        Write-Warning "MISSING: $($decoy.SamAccountName) not found — may have been removed"
    }
}
```

---

## 12. Bulk Cleanup

Remove all deployed decoys after an engagement or when rotating to a new set of decoys.

```powershell
$cred = Get-Credential -Message "Domain Admin credentials for cleanup"
$dc   = "DC01.corp.local"

# Read the deployment report to know what to remove
$deployedDecoys = Import-Csv ".\reports\F4keH0und_Report_latest.csv"

# Dry run first
foreach ($decoy in $deployedDecoys) {
    Remove-F4keH0undDecoy `
        -Identity $decoy.SamAccountName `
        -Server $dc `
        -Credential $cred `
        -WhatIf
}

# Confirm before live run
$confirm = Read-Host "Proceed with live cleanup? (yes/no)"
if ($confirm -eq "yes") {
    foreach ($decoy in $deployedDecoys) {
        Remove-F4keH0undDecoy `
            -Identity $decoy.SamAccountName `
            -Server $dc `
            -Credential $cred `
            -Verbose
    }
    Write-Host "Cleanup complete." -ForegroundColor Green
}
```

**What Remove-F4keH0undDecoy does for recycled objects:**

For objects that were recycled (not created fresh), the removal process:
1. Removes any SPNs that were added.
2. Removes group memberships that were added.
3. Reverts the description to its original value.
4. Removes the `TrustedForDelegation` flag if it was set.
5. **Does not delete the underlying AD object** — the stale object is left in its original disabled state.

This is the key safety property: recycled objects are never deleted, only restored to their pre-recycling state.

---

## See Also

- [README.md](README.md) — Overview, quick start, and feature reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module internals and extension points
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
