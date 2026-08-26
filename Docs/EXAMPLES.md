# F4keH0und - Last Generation — Deployment Examples

This file contains annotated, real-world deployment scenarios for F4keH0und - Last Generation. Each example is self-contained and can be run directly after importing the module.

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
13. [Inventory Interface](#13-inventory-interface)
14. [Lifecycle Management](#14-lifecycle-management)
15. [Parity Coverage and Sync](#15-parity-coverage-and-sync)
16. [Windows Artifact Lifecycle (WinRM/PSRP)](#16-windows-artifact-lifecycle-winrmpsrp)
17. [Windows Inventory Filtering](#17-windows-inventory-filtering)
18. [Token-Priority Workflow (Phase 4)](#18-token-priority-workflow-phase-4)
19. [Token Trigger Correlation & Alert Scoring](#19-token-trigger-correlation--alert-scoring)
20. [Telemetry Connector Presets (SIEM/SOAR)](#20-telemetry-connector-presets-siemsoar)
21. [Phase 5 Rollout Profiles](#21-phase-5-rollout-profiles)
22. [Phase 5 Drift Checks](#22-phase-5-drift-checks)
23. [Phase 5 Response Playbooks](#23-phase-5-response-playbooks)
24. [Identity-Attribute Lure Expansion](#24-identity-attribute-lure-expansion)
25. [Canary Text-Token Packs](#25-canary-text-token-packs)
26. [Service Credential Packs (Vault-Style)](#26-service-credential-packs-vault-style)

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
$kerberoastTargets |
    Select-Object ID, Rank,
        @{Name='SPN';Expression={ $_.Template.ServicePrincipalName }},
        @{Name='ConstrainedRole';Expression={ $_.Template.ConstrainedRoleLure }},
        @{Name='GroupsToAdd';Expression={ @($_.Template.GroupsToAdd) -join ';' }} |
    Format-Table -AutoSize

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

If the constrained-role group lure is present, add group-membership change monitoring for the decoy account to capture role-enumeration and abuse attempts in the same workflow.

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
# Ensure Graph session is established for Entra operations
Connect-MgGraph -Scopes "Application.ReadWrite.All","User.ReadWrite.All","Directory.ReadWrite.All"

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

**Current Entra decoy families:**

- `EntraServicePrincipalDecoy`
- `EntraGuestUserDecoy`
- `EntraAppRegistrationDecoy`

All three are recycling-first and are transformed through `Set-PrivateEntraDecoyPrincipal`.

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

**Current removal behavior:**

`Remove-F4keH0undDecoy` performs lifecycle cleanup by:
1. Removing group memberships where applicable.
2. Removing the target decoy object (`User`, `Computer`, or `Group`) from AD.

For environments that require restore-in-place recycling reversal (instead of object deletion), use a dry run first and plan the restoration workflow explicitly.

---

## 13. Inventory Interface

Use the unified inventory interface to review deceptive elements, deployment location, and current status.

```powershell
$cred = Get-Credential

# Persistent inventory backend with live AD checks
Get-F4keH0undInventory -Source Events -Server "DC01.corp.local" -Credential $cred |
    Format-Table Identity, DecoyType, Platform, Status, Location, DeployedAt -AutoSize

# Full lifecycle history including removed decoys
Get-F4keH0undInventory -Source Events -IncludeRemoved -PreferSnapshot -SkipLiveStatus |
    Sort-Object LastUpdated -Descending |
    Select-Object -First 20

# Historical inventory across report files only
Get-F4keH0undInventory -Source Reports -AllReports -SkipLiveStatus |
    Sort-Object DeployedAt -Descending |
    Select-Object -First 20
```

---

## 14. Lifecycle Management

Perform lifecycle operations on existing AD and Entra decoys without redeploying.

```powershell
$cred = Get-Credential
$dc   = "DC01.corp.local"

# Update metadata and relationships
Update-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User `
    -Description "Legacy SQL service account" `
    -AddGroups "DnsAdmins" `
    -Server $dc -Credential $cred

# Temporarily disable and then re-enable the decoy
Disable-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User -Server $dc -Credential $cred
Enable-F4keH0undDecoy  -Identity "svc_sql_legacy" -ObjectType User -Server $dc -Credential $cred

# Confirm lifecycle events are persisted
Get-F4keH0undInventory -Source Events -IncludeRemoved -SkipLiveStatus |
    Where-Object Identity -eq "svc_sql_legacy" |
    Format-Table Identity, LastAction, Status, LastUpdated -AutoSize

# Entra lifecycle operations
Update-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal `
    -Description "Legacy BI Analytics Connector - Last Generation"

Disable-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal
Enable-F4keH0undDecoy  -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal

# Optional cleanup in Entra
Remove-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -DecoyType ServicePrincipal -WhatIf
```

---

## 15. Parity Coverage and Sync

Measure AD/Entra parity and then run targeted Entra remediation planning (or execution).

```powershell
# Step 1: Baseline coverage from persistent events without AD live lookups
$coverage = Test-F4keH0undCoverage -Source Events -PreferSnapshot -SkipLiveStatus

$coverage | Select-Object IsParityMet, ADLifecycleCoveragePercent, EntraLifecycleCoveragePercent, EntraToADActiveRatio
$coverage.FamilyStatus | Format-Table Family, ADActiveCount, EntraActiveCount, TargetEntraCount, Gap, IsMet -AutoSize

# Step 2: Build Entra parity sync plan
$plan = Sync-F4keH0undEntraParity `
    -AzureHoundPath "C:\AzureHound_Data\" `
    -TargetParityRatio 1.0 `
    -MaxDeployments 3

$plan.SelectedOpportunities | Format-Table OpportunityId, DecoyType, Rank, Family, IdentityHint -AutoSize

# Inspect Entra lure metadata before execution
$plan.SelectedOpportunities |
    Where-Object { $_.DecoyType -like 'Entra*' } |
    Select-Object OpportunityId, DecoyType, Rank,
        @{Name='LureTheme';Expression={ $_.LureTheme }},
        @{Name='Consent';Expression={ $_.ConsentScopeBait }},
        @{Name='CABypass';Expression={ $_.ConditionalAccessBypassHint }},
        @{Name='OAuthPermission';Expression={ $_.OAuthPermissionBait }},
        @{Name='GrantType';Expression={ $_.OAuthGrantTypeBait }},
        @{Name='RedirectUri';Expression={ $_.OAuthRedirectUriBait }} |
    Format-Table -AutoSize

# Step 3: Safe execution preview
Sync-F4keH0undEntraParity `
    -AzureHoundPath "C:\AzureHound_Data\" `
    -TargetParityRatio 1.0 `
    -MaxDeployments 3 `
    -Execute -WhatIf
```

---

## 16. Windows Artifact Lifecycle (WinRM/PSRP)

Deploy and manage Windows-only deceptive artifact elements from any `pwsh` host (macOS/Linux/Windows) over WinRM/PSRP.

```powershell
# Cross-platform control plane (run from macOS/Linux/Windows with PowerShell 7+)
# Targets are Windows hosts only.
$cred = Get-Credential

# 1) Discover available Windows element families/types
Get-F4keH0undElementType -Detailed |
    Sort-Object Family, DetectionScore -Descending |
    Format-Table TypeId, Family, CostScore, DetectionScore, TelemetryProfile -AutoSize

# 2) Deploy API-hook bait artifacts (safe preview first)
New-F4keH0undElement `
    -ElementType ApiHookConfigDecoy `
    -ComputerName WIN-APP-01,WIN-APP-02 `
    -TemplateData @{ ApiBaseUrl = "https://legacy-api.internal.corp"; IntegrationName = "LegacyBillingSync" } `
    -Tag "phase3","api" `
    -Credential $cred `
    -WhatIf

# 3) Live deployment with pass-through results
$deployed = New-F4keH0undElement `
    -ElementType ApiHookConfigDecoy `
    -ComputerName WIN-APP-01,WIN-APP-02 `
    -TemplateData @{ ApiBaseUrl = "https://legacy-api.internal.corp"; IntegrationName = "LegacyBillingSync" } `
    -Tag "phase3","api" `
    -Credential $cred `
    -PassThru

$deployed | Format-Table ElementId, ComputerName, Status, BasePath -AutoSize

# 4) Update, disable, re-enable, remove (full lifecycle)
$elementId = $deployed[0].ElementId

Update-F4keH0undElement -ElementId $elementId -TemplateData @{ ApiBaseUrl = "https://legacy-api2.internal.corp" } -Credential $cred
Disable-F4keH0undElement -ElementId $elementId -Reason "maintenance" -Credential $cred
Enable-F4keH0undElement -ElementId $elementId -Credential $cred
Remove-F4keH0undElement -ElementId $elementId -Credential $cred -WhatIf
```

---

## 17. Windows Inventory Filtering

Use inventory filters to build a clear interface for deployed artifact elements, where they live, and their current lifecycle status.

```powershell
# All Windows elements, latest first
Get-F4keH0undInventory -Source Events -Platform Windows -SkipLiveStatus |
    Format-Table Identity, DecoyType, Status, Location, LastUpdated -AutoSize

# Family-focused view: API bait currently armed
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementFamily ApiHookBait `
    -Status Armed `
    -SkipLiveStatus |
    Select-Object Identity, DecoyType, Status, @{Name='ComputerName';Expression={ $_.Metadata.ComputerName }}, Location, LastUpdated

# Host-focused view: all elements on a specific server
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ComputerName WIN-APP-01 `
    -IncludeRemoved `
    -SkipLiveStatus |
    Sort-Object LastUpdated -Descending

# Type-focused view: service-lure artifacts only
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementType ServiceDefinitionDecoy `
    -SkipLiveStatus
```

---

## 18. Token-Priority Workflow (Phase 4)

Use ranked Windows opportunities for explicit hosts, then deploy identity/token bait with the dedicated token command.

```powershell
$bhPath = "C:\BH_Data"
$targets = @("WIN-APP-01", "WIN-APP-02")

# 1) Include Windows artifact opportunities in analysis
$opportunities = Find-F4keH0undOpportunity `
    -BloodHoundPath $bhPath `
    -WindowsComputerName $targets `
    -MaxWindowsElementOpportunities 6

$opportunities |
    Where-Object Strategy -eq "Artifact" |
    Select-Object ID, Rank, DecoyType, ElementFamily, Justification |
    Format-Table -AutoSize

# 2) Deploy identity breadcrumb token bait
New-F4keH0undToken `
    -TokenType IdentityBreadcrumb `
    -ComputerName $targets `
    -TemplateData @{ PrivilegedSamAccountName = "svc_legacy_sync"; EntraUserPrincipalName = "svc-legacy-sync@contoso.onmicrosoft.com" } `
    -Tag "identity","priority" `
    -WhatIf

# 3) Deploy cloud API canary token bait
$tokenDeploy = New-F4keH0undToken `
    -TokenType CloudApiCanary `
    -ComputerName $targets `
    -Tag "cloud","token" `
    -Credential (Get-Credential) `
    -PassThru

$tokenDeploy | Format-Table ElementId, ElementType, ComputerName, Status, BasePath -AutoSize

# 4) Validate token families in inventory interface
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementFamily IdentityTokenBait,CloudTokenBait,CredentialBait `
    -SkipLiveStatus |
    Sort-Object LastUpdated -Descending |
    Format-Table Identity, DecoyType, Status, @{Name='Computer';Expression={ $_.Metadata.ComputerName }}, LastUpdated -AutoSize
```

---

## 19. Token Trigger Correlation & Alert Scoring

Register a trigger event from telemetry, then query prioritized alerts by severity/score.

```powershell
$identity = "fhlg-win-identitybreadcrumbtokendecoy-a1b2c3d4e5f6"

# 1) Record trigger from telemetry pipeline (SIEM/SOAR handoff)
Register-F4keH0undTokenTrigger `
    -Identity $identity `
    -TriggerType TokenUse `
    -TriggerSource "Sysmon:EventID11" `
    -Actor "CORP\\j.smith" `
    -EvidenceRef "case-427" `
    -SignalCount 3 `
    -Confidence 92 `
    -TokenIdentifier "sha256:1234567890abcdef" `
    -PassThru |
    Format-List Identity, TriggerCount, TokenCorrelationStatus, AlertScore, AlertSeverity

# 2) Query high-confidence alerts only
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -AlertSeverity High,Critical `
    -MinAlertScore 65 `
    -SkipLiveStatus |
    Sort-Object AlertScore -Descending |
    Select-Object Identity, DecoyType, Status, TriggerCount, LastTriggeredAt, TokenCorrelationStatus, AlertScore, AlertSeverity

# 3) Filter by one decoy family with active triggers
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementFamily IdentityTokenBait `
    -MinAlertScore 40 `
    -SkipLiveStatus
```

---

## 20. Telemetry Connector Presets (SIEM/SOAR)

Use connector presets to map raw Sysmon/Security events into `Register-F4keH0undTokenTrigger` fields.

```powershell
# Example A: Sysmon Event ID 3 (network connect) from SIEM parser
$sysmonEvent = @{
    Identity            = "fhlg-win-cloudapicanarytokendecoy-3f1c9a2d4e6b"
    User                = "CORP\\j.smith"
    Computer            = "WIN-API-01"
    EventRecordId       = "sysmon-92117"
    DestinationHostname = "graph.microsoft.com"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset SysmonEvent3NetworkConnect `
    -TelemetryPayload $sysmonEvent `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, LastTriggerActor, AlertScore, AlertSeverity

# Example B: Windows Security 4624 logon event
$securityEvent = @{
    DecoyIdentity   = "svc_legacy_sync"
    SubjectUserName = "backup.operator"
    WorkstationName = "WKST-017"
    EventRecordId   = "security-55102"
    TargetUserName  = "svc_legacy_sync"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset WindowsSecurity4624Logon `
    -TelemetryPayload $securityEvent `
    -Platform AD `
    -ObjectType User `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, TokenCorrelationStatus, AlertScore, AlertSeverity

# Prioritize triggered artifacts from mapped connector flow
Get-F4keH0undInventory `
    -Source Events `
    -AlertSeverity High,Critical `
    -MinAlertScore 65 `
    -SkipLiveStatus |
    Sort-Object AlertScore -Descending |
    Select-Object Identity, DecoyType, Platform, LastTriggerSource, AlertScore, AlertSeverity
```

---

## 21. Phase 5 Rollout Profiles

Use `Lab`, `Pilot`, and `Production` rollout profiles to apply safer defaults for deployment throttle, Entra deployment caps, and role-assignment guardrails.

```powershell
# Inspect configured rollout profile defaults
Get-F4keH0undConfig -Section RolloutProfiles | Format-List

# Windows artifact deployment using Lab profile (WhatIf-by-default unless explicitly overridden)
New-F4keH0undElement `
    -ElementType ApiHookConfigDecoy `
    -ComputerName WIN-APP-01,WIN-APP-02 `
    -RolloutProfile Lab `
    -TemplateData @{ ApiBaseUrl = "https://legacy-api.internal.corp" }

# Token deployment with Production profile defaults
New-F4keH0undToken `
    -TokenType CloudApiCanary `
    -ComputerName WIN-API-01 `
    -RolloutProfile Production `
    -PassThru

# Entra parity sync with Pilot profile guardrails
Sync-F4keH0undEntraParity `
    -AzureHoundPath "C:\AzureHound_Data\" `
    -RolloutProfile Pilot `
    -Execute `
    -WhatIf
```

---

## 22. Phase 5 Drift Checks

Run lightweight stale-template drift analysis and get redesign guidance before regular refresh windows.

```powershell
# Fast drift summary (lightweight mode skips live AD checks by default)
$drift = Test-F4keH0undDrift -Source Events -PreferSnapshot
$drift | Format-List TotalEvaluated, DriftedCount, DriftSeverityCounts

# Review highest-priority redesign candidates
$drift.Findings |
    Where-Object Drifted |
    Sort-Object DriftScore -Descending |
    Select-Object -First 10 Identity, Platform, DecoyType, DriftSeverity, DriftScore, RecommendedAction

# Windows token-focused rotation list
Test-F4keH0undDrift `
    -Platform Windows `
    -MaxTokenAgeDays 14 `
    -MinTriggerCountForRedesign 1 `
    -AsList |
    Where-Object { $_.Drifted -and $_.DecoyType -match 'Token|Credential|Identity' } |
    Select-Object Identity, DriftReasons, SuggestedCommand
```

---

## 23. Phase 5 Response Playbooks

Generate a severity-specific incident playbook from current inventory and drift context.

```powershell
# Generate High-severity token-trigger response playbook
./scripts/New-TokenTriggerResponsePlaybook.ps1 -AlertSeverity High

# Generate Critical playbook with Events inventory focus
./scripts/New-TokenTriggerResponsePlaybook.ps1 `
    -AlertSeverity Critical `
    -Source Events `
    -PreferSnapshot `
    -MaxFindings 15

# Generate focused playbook for one identity
./scripts/New-TokenTriggerResponsePlaybook.ps1 `
    -AlertSeverity Critical `
    -Identity fhlg-win-cloudapicanarytokendecoy-a1b2c3d4e5f6
```

---

## 24. Identity-Attribute Lure Expansion

Inspect and deploy low-cost identity-persona attributes for AD and Entra decoys.

```powershell
# Review AD opportunity templates with persona fields
Find-F4keH0undOpportunity -BloodHoundPath "C:\BH_Data\" -PreferRecycling |
    Where-Object { $_.DecoyType -in @('StaleAdminLure','KerberoastableUser','DNSAdminUser') } |
    Select-Object -First 5 DecoyType, Strategy, @{Name='Template';Expression={ $_.Template }}

# Review Entra opportunity templates with owner/group hints
Find-F4keH0undOpportunity -AzureHoundPath "C:\AzureHound_Data\" -EntraPreferRecycling |
    Where-Object { $_.DecoyType -like 'Entra*' } |
    Select-Object -First 5 DecoyType, Rank, @{Name='IdentityOwnerHint';Expression={ $_.Template.IdentityOwnerHint }}, @{Name='GroupHint';Expression={ $_.Template.GroupHint }}

# Deploy selected opportunities and persist identity-attribute metadata in inventory
New-F4keH0undDecoy -BloodHoundPath "C:\BH_Data\" -Execute -PreferRecycling -WhatIf

Get-F4keH0undInventory -Source Events -Platform AD -SkipLiveStatus |
    Select-Object -First 10 Identity, DecoyType, Status, Metadata
```

---

## 25. Canary Text-Token Packs

Deploy low-cost script/config/docs canary packs and register lightweight file-access triggers using the dedicated connector presets.

```powershell
# 1) Deploy canary text-token pack to repository-adjacent Windows hosts
$pack = New-F4keH0undToken `
    -TokenType CanaryTextPack `
    -ComputerName "WIN-DEV-01" `
    -Name "IdentityRepo-CanaryPack" `
    -TemplateData @{
        RepositoryHint   = "legacy-identity-automation"
        IdentityOwnerHint = "identity.ops@contoso.com"
        GroupHint         = "Identity-Engineering"
    } `
    -PassThru

$pack | Format-Table ElementId, ElementType, ComputerName, BasePath, Status -AutoSize
$packRecord = @($pack)[0]

# 2) Simulate Sysmon file-create telemetry (identity resolved by artifact path hints)
$sysmonFileEvent = @{
    TargetFilename = "C:\ProgramData\F4keH0und-LG\Elements\$($packRecord.ElementId)\docs\IdentityRepo-CanaryPack-operator-runbook.decoy.md"
    User           = "CORP\\j.smith"
    Computer       = "WIN-DEV-01"
    EventRecordId  = "sysmon-22007"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset CanaryTextPackSysmonFileCreate `
    -TelemetryPayload $sysmonFileEvent `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, TokenCorrelationStatus, AlertScore, AlertSeverity

# 3) Triage highest-confidence triggered token elements
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementFamily TokenTextBait,IdentityTokenBait,CloudTokenBait,CredentialBait `
    -AlertSeverity High,Critical `
    -SkipLiveStatus |
    Sort-Object AlertScore -Descending |
    Select-Object Identity, DecoyType, Status, LastTriggerSource, AlertScore, AlertSeverity
```

---

## 26. Service Credential Packs (Vault-Style)

Deploy vault-like service credential bait and register lightweight trigger telemetry using the service-pack connector presets.

```powershell
# 1) Deploy service credential pack to Windows identity-management host
$pack = New-F4keH0undToken `
    -TokenType ServiceCredentialPack `
    -ComputerName "WIN-IDM-01" `
    -Name "VaultSync-CredPack" `
    -TemplateData @{
        ServiceName       = "LegacyIdentitySync"
        ServiceAccount    = "CORP\\svc_identity_sync"
        SecretReference   = "kv://prod/legacy/identity-sync"
        VaultPath         = "C:\ProgramData\VaultCache\legacy-identity-sync"
        IdentityOwnerHint = "identity.ops@contoso.com"
        GroupHint         = "Identity-Engineering"
    } `
    -PassThru

$pack | Format-Table ElementId, ElementType, ComputerName, BasePath, Status -AutoSize
$packRecord = @($pack)[0]

# 2) Simulate Sysmon file-create telemetry for vault artifact access
$serviceEvent = @{
    TargetFilename = "C:\ProgramData\F4keH0und-LG\Elements\$($packRecord.ElementId)\vault\VaultSync-CredPack\service-credentials.decoy.json"
    User           = "CORP\\j.smith"
    Computer       = "WIN-IDM-01"
    EventRecordId  = "sysmon-31009"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset ServiceCredentialPackSysmonFileCreate `
    -TelemetryPayload $serviceEvent `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, TokenCorrelationStatus, AlertScore, AlertSeverity

# 3) Review service-credential bait triage view
Get-F4keH0undInventory `
    -Source Events `
    -Platform Windows `
    -ElementFamily ServiceCredentialBait,CredentialBait,IdentityTokenBait `
    -AlertSeverity Medium,High,Critical `
    -SkipLiveStatus |
    Sort-Object AlertScore -Descending |
    Select-Object Identity, DecoyType, Status, LastTriggerSource, AlertScore, AlertSeverity
```

---

## See Also

- [README.md](../README.md) — Overview, quick start, and feature reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module internals and extension points
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
