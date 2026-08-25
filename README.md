# F4keH0und - Last Generation
*A PowerShell-first deception framework for Active Directory & Entra ID with recycling-first deployment and lifecycle management.*

<p align="center">
  <img src="https://deceiver.io/wp-content/uploads/2025/09/f4keh0und-git.png" alt="F4keH0und - Last Generation logo" width="50%">
</p>

[![CI](https://github.com/DEF-CON-Group-420/F4keH0und/actions/workflows/ci.yml/badge.svg)](https://github.com/DEF-CON-Group-420/F4keH0und/actions/workflows/ci.yml)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-1f6feb)](https://github.com/PowerShell/PowerShell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-RSAT-0A66C2)](https://learn.microsoft.com/powershell/module/activedirectory/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-Enabled-0078D4?logo=microsoftazure&logoColor=white)](https://learn.microsoft.com/powershell/microsoftgraph/)
[![BloodHound](https://img.shields.io/badge/BloodHound-SharpHound%20%2B%20AzureHound-8A2BE2)](https://bloodhound.specterops.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Fork me on GitHub](https://img.shields.io/badge/Fork%20me%20on-GitHub-blue?logo=github)](https://github.com/DEF-CON-Group-420/F4keH0und/fork)

---

## 📖 Description

**F4keH0und - Last Generation** is a PowerShell module for blue teams, red teams, and security researchers. It analyzes BloodHound collector output (SharpHound and AzureHound) to identify high-value deception opportunities in Active Directory and Microsoft Entra ID, then deploys and tracks decoy objects that blend into the environment.

The Last Generation architecture uses a **recycling-first philosophy**: rather than creating brand-new objects that attackers can trivially detect, F4keH0und repurposes stale or disabled AD objects that already exist — preserving their original RIDs, creation timestamps, and security history.

---

## 🚨 The RID Anomaly Problem

When a new AD object is created, Windows assigns it a sequentially incremented **Relative Identifier (RID)**. An attacker enumerating the domain can sort all objects by RID and immediately spot objects that were created recently — long after the domain was established. This is known as the **RID anomaly** and it betrays newly created decoys instantly.

```powershell
# What an attacker sees when you create new decoys:
# ObjectSID                         whenCreated           SamAccountName
# S-1-5-21-...-502                  1998-03-15 09:12:01   krbtgt          # real, old
# S-1-5-21-...-1103                 2019-07-22 14:05:33   john.smith      # real, old
# S-1-5-21-...-1104                 2019-07-23 11:30:09   jane.doe        # real, old
# ...
# S-1-5-21-...-4721                 2025-10-01 08:00:00   svc_mssql_prod  # YOUR NEW DECOY — obvious!
```

F4keH0und solves this by **recycling existing stale objects** instead of creating new ones:

```powershell
# What an attacker sees when you recycle a stale object:
# ObjectSID                         whenCreated           SamAccountName
# S-1-5-21-...-502                  1998-03-15 09:12:01   krbtgt
# S-1-5-21-...-1103                 2019-07-22 14:05:33   john.smith
# S-1-5-21-...-1104                 2019-07-23 11:30:09   jane.doe     <- recycled as decoy
# ...
# S-1-5-21-...-4721                 2025-10-01 08:00:00   svc_mssql_prod  # just another new account
```

The recycled object keeps its original RID (`1104`) and `whenCreated` timestamp, so it looks like it has always been there.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                F4keH0und - Last Generation                          │
│              Recycling-First PowerShell Architecture                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │ BloodHound   │    │  Find-Opportunity │    │  Recycling       │  │
│  │ JSON Data    │───▶│  (Analysis)       │───▶│  Engine          │  │
│  │ SharpHound / │    │                  │    │  Find-Recyclable  │  │
│  │ AzureHound   │    │  Ranks: Critical  │    │  Object          │  │
│  └──────────────┘    │  High / Low       │    └────────┬─────────┘  │
│                      └──────────────────┘             │             │
│                                                        │             │
│                      ┌──────────────────┐             │             │
│                      │  New-F4keH0und   │◀────────────┘             │
│                      │  Decoy           │                           │
│                      │  (Deployment)    │                           │
│                      └────────┬─────────┘                           │
│                               │                                     │
│              ┌────────────────┼────────────────┐                   │
│              ▼                ▼                 ▼                   │
│     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│     │ Set-Decoy    │ │ Set-Decoy    │ │ Set-Decoy    │            │
│     │ User         │ │ Computer     │ │ Group / SPN  │            │
│     │ (Recycle)    │ │ (Recycle)    │ │ / ACL        │            │
│     └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  Active Directory / Entra ID                 │   │
│  │  Stale objects repurposed in-place — RID & timestamp intact  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

For a detailed module structure, data-flow diagrams, and design decisions see [Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md).

---

## ✨ Features

- **Recycling-First Engine**: Scans stale/disabled identities and repurposes them to preserve RID and creation timelines.
- **Identity-First Priority**: Focuses on high-detection decoys like stale admins, token-bearing identities, and privileged account lures.
- **AD + Entra Coverage**: Supports hybrid deception analysis for on-prem AD and Microsoft Entra ID.
- **Cross-Platform PowerShell**: Designed for Windows, macOS, and Linux when required PowerShell modules are installed.
- **Lifecycle Controls**: `New-`, `Get-`, and `Remove-` workflows support deployment, status tracking, and cleanup.
- **Inventory Interface**: `Get-F4keH0undInventory` provides a consolidated view of deployed deceptive elements and status.
- **Relationship Graphing**: `Add-F4keH0undRelationship` builds deceptive graph edges for path-based attacker detection.
- **Safe by Default**: Full `-WhatIf` and `-Confirm` support; no changes occur without explicit approval.
- **Automated Reporting**: Generates CSV handover reports for SecOps and purple-team operations.

---

## 🗺️ Last Generation Focus

- **PowerShell-first, cross-platform**: Keep `pwsh` as the primary runtime while maintaining compatibility for Windows, macOS, and Linux.
- **Unified deceptive-element interface**: Track tokens, identities, services, and other decoys with deployment location and status visibility.
- **AD + Entra parity**: Expand Entra coverage to mirror the breadth and lifecycle depth currently available for AD.
- **Lifecycle completeness**: Extend command surface for create, inspect, update, redesign, disable, and remove workflows.
- **Identity and token priority**: Lead with low-cost/high-detection elements like identity decoys, fake credentials, and token bait.

For execution details and phased delivery, see [Docs/LAST-GENERATION-ROADMAP.md](Docs/LAST-GENERATION-ROADMAP.md).

---

## 🎯 Decoy Types

### 1 — StaleAdminLure *(Rank: Critical)*

Recycles a disabled, formerly privileged AD user account and places it near sensitive groups as a honey account. Attackers targeting dormant admin accounts will trigger alerts when they interact with it.

```powershell
# Example opportunity output
DecoyType      : StaleAdminLure
Rank           : Critical
Source         : Recycle          # <- recycled, not created
Identity       : CN=j.harris,OU=Legacy,DC=contoso,DC=local
StalenessScore : 87
```

### 2 — KerberoastableUser *(Rank: High)*

Recycles a stale user and adds a tempting Service Principal Name (SPN). Any Kerberoasting tool (`Rubeus`, `Impacket`) that requests a TGS for this SPN generates an immediate alert.

```powershell
# SPN added during recycling
ServicePrincipalName : MSSQLSvc/prod-sql01.contoso.local:1433
```

### 3 — UnconstrainedDelegationComputer *(Rank: High)*

Recycles a stale computer object and sets the `TrustedForDelegation` flag. Attackers scanning for unconstrained delegation targets will find this decoy and attempt to exploit it.

```powershell
# Computer recycled with delegation flag
TrustedForDelegation : True
```

### 4 — DNSAdminUser *(Rank: Critical)*

Recycles a stale user and adds it to the `DnsAdmins` group — a highly desirable privilege escalation target. Any enumeration or exploitation attempt against this account alerts defenders.

```powershell
# Group membership added
MemberOf : CN=DnsAdmins,CN=Users,DC=contoso,DC=local
```

### 5 — ACLAttackPath *(Rank: High)*

Creates a synthetic multi-hop ACL attack chain between recycled objects, designed to appear in BloodHound graph traversals. Attackers following the path will interact with monitored decoys at every step.

```powershell
# Relationship added
Add-F4keH0undRelationship -SourceIdentity "decoy_user_01" `
    -TargetIdentity "decoy_group_01" `
    -RelationshipType "GenericWrite"
```

> **Entra ID Bonus — PrivilegedEntraSP *(Rank: Critical)***: For hybrid environments, F4keH0und deploys a decoy Service Principal with an enticing high-privilege role assignment in Entra ID.

---

## 🆚 Recycling vs. Creation

| | Recycling (Last Generation default) | Creating new objects |
|---|---|---|
| **RID** | Original RID preserved | Sequential, obviously recent |
| **whenCreated** | Original timestamp preserved | Current date — stands out |
| **Blend-in factor** | ✅ Indistinguishable from real objects | ❌ Trivially identified by RID sort |
| **AD noise** | Minimal — modifies existing object | Creates entirely new object |
| **Safety** | Only touches disabled, stale objects | May conflict with naming schemes |
| **Staleness Score** | Built-in suitability scoring | Not applicable |

---

## ⚙️ Prerequisites

1. **PowerShell 7+**: Required for consistent behavior across Windows, macOS, and Linux.
2. **Permissions**: You have two options:
   - **Run As Privileged User**: Run PowerShell as a user with permissions in the target domain.
   - **Use `-Credential` Parameter**: Supply privileged credentials at runtime (recommended for cross-domain).
3. **Module Requirements**:
   - **ActiveDirectory** module for on-prem AD operations.
   - **Microsoft.Graph** modules for Entra discovery/recycling flows.
4. **Network Connectivity**: TCP 9389 (AD Web Services) must be reachable for AD operations using `-Server`.
5. **BloodHound Data**: JSON output from recent SharpHound and/or AzureHound collection runs.

---

## 🚀 Quick Start

### Step 1 — Install

```powershell
# Clone the repository
git clone https://github.com/DEF-CON-Group-420/F4keH0und.git
Set-Location ./F4keH0und

# Reinstall from this source clone (cross-platform)
./Reinstall-F4keH0und.ps1

# Import and verify
Import-Module F4keH0und -Force
Get-Module F4keH0und
```

> **Updating the module later?**
> After a `git pull`, the copy in your user module path from `$env:PSModulePath` is **not** updated automatically —
> PowerShell will keep loading the old cached version. Run `Reinstall-F4keH0und.ps1` to wipe every stale copy and
> reinstall from your local clone:
> ```powershell
> cd /path/to/F4keH0und
> ./Reinstall-F4keH0und.ps1 -PullLatest
> ```
> See the [Troubleshooting](#-troubleshooting) section for details.

### Step 2 — Analyze

```powershell
# Analyze AD data and discover recycling + creation opportunities
$bloodHoundPath = Join-Path $PWD 'BH_Data'
$opportunities = Find-F4keH0undOpportunity -BloodHoundPath $bloodHoundPath -PreferRecycling -Verbose

# Review what was found
$opportunities | Format-Table DecoyType, Rank, Source, Identity, StalenessScore -AutoSize
```

### Step 3 — Dry Run

```powershell
# Always test with -WhatIf first — no changes are made
New-F4keH0undDecoy -BloodHoundPath $bloodHoundPath -Execute -PreferRecycling -WhatIf
```

### Step 4 — Deploy

```powershell
# Domain-joined machine — use existing session
New-F4keH0undDecoy -BloodHoundPath $bloodHoundPath -Execute -PreferRecycling

# Bastion / cross-domain — supply server and credentials
New-F4keH0undDecoy -BloodHoundPath $bloodHoundPath -Execute -PreferRecycling `
    -Server "DC01.target.local" -Credential (Get-Credential)
```

### Step 5 — Clean Up

```powershell
# Remove a specific decoy (dry run first)
Remove-F4keH0undDecoy -Identity "j.harris" -WhatIf `
    -Server "DC01.target.local" -Credential (Get-Credential)

# Live removal
Remove-F4keH0undDecoy -Identity "j.harris" `
    -Server "DC01.target.local" -Credential (Get-Credential)
```

### Step 6 — Inventory Interface

```powershell
# Show latest deceptive element inventory with live AD status checks
Get-F4keH0undInventory -Server "DC01.target.local" -Credential (Get-Credential) |
    Format-Table Identity, DecoyType, Platform, Status, Location, DeployedAt -AutoSize

# Historical view from all report files (recorded state only)
Get-F4keH0undInventory -AllReports -SkipLiveStatus |
    Sort-Object DeployedAt -Descending
```

---

## ⚙️ Configuration

F4keH0und is configured via `config.json` in the module root. Use `config.example.json` as your starting point.

### RecyclingPreferences

Controls how stale objects are discovered and prioritized.

| Key | Default | Description |
|-----|---------|-------------|
| `PreferRecycling` | `true` | Prioritize recycling over creation |
| `RecyclingOnly` | `false` | Return nothing if no recyclable objects exist (strict mode) |
| `MinimumObjectAgeDays` | `180` | Ignore objects newer than this (prevents recycling recently disabled accounts) |
| `MaximumObjectAgeDays` | `3650` | Ignore objects older than this (~10 years — may still be referenced) |
| `MaxRecyclableUsersPerScan` | `50` | Cap on recyclable user candidates per scan |
| `MaxRecyclableComputersPerScan` | `20` | Cap on recyclable computer candidates per scan |
| `MaxRecyclableGroupsPerScan` | `20` | Cap on recyclable group candidates per scan |

### SafetyFilters

Defines what must never be recycled.

| Key | Default | Description |
|-----|---------|-------------|
| `ExcludedOUs` | `["OU=VIP,DC=*", ...]` | OU paths to skip (wildcards supported) |
| `ProtectedUserPatterns` | `["^Administrator$", ...]` | Regex patterns — matching usernames are never recycled |
| `ProtectedComputerPatterns` | `["^DC\\d*$", ...]` | Regex patterns — matching computer names are never recycled |
| `ProtectedGroupPatterns` | `["^Domain Admins$", ...]` | Regex patterns — matching group names are never recycled |
| `RequireDisabledAccounts` | `true` | Only recycle accounts that are already disabled |
| `RequireEmptyGroups` | `true` | Only recycle groups that have no members |
| `MinimumPasswordAgeDays` | `180` | Only recycle users whose password is at least this old |

### DeploymentSettings

| Key | Default | Description |
|-----|---------|-------------|
| `DefaultDecoyPrefix` | `""` | Prefix prepended to names of newly created (non-recycled) objects |
| `DefaultDecoySuffix` | `""` | Suffix appended to names of newly created objects |
| `ReportOutputPath` | `./reports` | Directory for CSV deployment reports |
| `AutoGenerateReport` | `true` | Automatically generate a report after deployment |
| `VerboseLogging` | `false` | Enable verbose output by default |

### Example Configuration

```json
{
  "RecyclingPreferences": {
    "PreferRecycling": true,
    "RecyclingOnly": false,
    "MinimumObjectAgeDays": 365,
    "MaximumObjectAgeDays": 3650
  },
  "SafetyFilters": {
    "ExcludedOUs": [
      "OU=VIP,DC=contoso,DC=local",
      "OU=Executives,DC=contoso,DC=local"
    ],
    "ProtectedUserPatterns": ["^admin", "^svc_prod"],
    "RequireDisabledAccounts": true
  },
  "DeploymentSettings": {
    "ReportOutputPath": "C:\\SecOps\\F4keH0und\\reports",
    "AutoGenerateReport": true
  }
}
```

### Validating Your Configuration

```powershell
Test-F4keH0undConfig -Verbose
```

---

## 🔒 Safety Features

F4keH0und is designed to be safe by default. The following guardrails are enforced at every stage:

| Feature | Description |
|---------|-------------|
| **-WhatIf support** | All deployment functions support `-WhatIf` — run a full dry run with zero AD writes |
| **-Confirm support** | Prompts for confirmation before each destructive action |
| **RequireDisabledAccounts** | Only considers accounts that are already disabled as recycling candidates |
| **ProtectedUserPatterns** | Built-in regex blocklist prevents recycling `Administrator`, `krbtgt`, `MSOL_*`, `AAD_*`, sync accounts, and more |
| **ExcludedOUs** | Wildcard-based OU exclusion prevents touching VIP, Executive, or Domain Controller OUs |
| **PrivilegedGroupNames** | Accounts currently in privileged groups are never recycled |
| **MinimumPasswordAgeDays** | Accounts with recent password changes are excluded (safety buffer) |
| **RequireEmptyGroups** | Groups with active members cannot be recycled |
| **Age window checks** | Objects must fall within the configured age window (MinimumObjectAgeDays to MaximumObjectAgeDays) |
| **StalenessScore threshold** | Low-scored objects are deprioritized automatically |

---

## 🔧 Advanced Usage

### Recycling-Only Mode

Enforce a strict "no new objects" policy — fail fast if no recyclable candidates exist:

```powershell
Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -RecyclingOnly -Verbose
```

### Custom Age Window

Target only objects in a specific staleness range:

```powershell
Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling `
    -RecyclingMinimumAgeDays 365 `
    -RecyclingMaximumAgeDays 1825  # 5 years
```

### OU Exclusions at Runtime

Override `config.json` OU exclusions on the fly:

```powershell
Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling `
    -ExcludeOUs @("OU=VIP,DC=contoso,DC=local", "OU=Finance,DC=contoso,DC=local")
```

### Entra ID Decoys

For hybrid environments, analyze AzureHound data alongside SharpHound:

```powershell
Find-F4keH0undOpportunity -AzureHoundPath C:\AzureHound_Data\
```

### View Raw Recyclable Candidates

Call the recycling engine directly to inspect candidates before deployment:

```powershell
$candidates = Find-F4keH0undRecyclableObject -Type User -MinimumAgeDays 180 -Verbose
$candidates | Select-Object SamAccountName, StalenessScore, DaysSinceCreation, RecommendedDecoyType |
    Format-Table -AutoSize
```

### Configuration Management

```powershell
# Read the full configuration
Get-F4keH0undConfig

# Read a specific section
Get-F4keH0undConfig -Section RecyclingPreferences

# Validate the configuration before deployment
Test-F4keH0undConfig -Verbose
```

---

## 🔧 Extending F4keH0und

The module is designed to be extended with new decoy types. Follow this 4-step process:

1. **Define the Logic**: Decide what BloodHound data to query and what decoy to build.
2. **Add Analysis Logic**: Edit `Public\Find-F4keH0undOpportunity.ps1` — add a new block that identifies targets and emits an opportunity object with a unique `DecoyType`.
3. **Add Ranking Logic**: Edit `Private\Get-F4keH0undRank.ps1` — add a new `case` to the `switch` statement for your `DecoyType`.
4. **Add Deployment Logic**: Edit `Public\New-F4keH0undDecoy.ps1` — add a new `case` to its `switch` statement, creating a private helper function (e.g., `Private\Set-PrivateADDecoyMyType.ps1`) to handle the AD write.

See [Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md) for a full walkthrough of all extension points.

---

## 🤝 Contributing

Contributions are welcome! See [Docs/CONTRIBUTING.md](Docs/CONTRIBUTING.md) for instructions on forking the repository, setting up your environment, and submitting pull requests.

---

## 🛠️ Troubleshooting

### "The 'ActiveDirectory' module is not installed"

Install RSAT on Windows:
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```
Or on Windows Server:
```powershell
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### "Access is denied" when querying AD

- Ensure you are running PowerShell as a user with at least **Domain User** read rights.
- For write operations (deploying decoys), you need **Domain Admin** or delegated create/modify permissions.
- For cross-domain operations, always pass `-Server` and `-Credential`:
  ```powershell
  New-F4keH0undDecoy ... -Server "DC01.target.local" -Credential (Get-Credential)
  ```

### No recycling opportunities found

- Lower `MinimumObjectAgeDays` or widen the age window in `config.json`.
- Check that `ExcludedOUs` patterns are not too broad.
- Run with `-Verbose` to see exactly which filters are eliminating candidates:
  ```powershell
  Find-F4keH0undOpportunity -BloodHoundPath C:\BH_Data\ -PreferRecycling -Verbose
  ```
- Use `Find-F4keH0undRecyclableObject` directly to see raw candidate counts:
  ```powershell
  Find-F4keH0undRecyclableObject -Type User -Verbose
  ```

### Config validation fails

```powershell
Test-F4keH0undConfig -Verbose
```
Check that all required keys exist and that regex patterns in `ProtectedUserPatterns` are valid.

### WhatIf shows changes I didn't expect

Review the `config.json` defaults — particularly `DefaultDecoyPrefix`/`DefaultDecoySuffix` — which affect naming of newly created (non-recycled) objects.

### `-PreferRecycling` (or another new parameter) is reported as unknown after updating

**Cause:** PowerShell is loading a stale copy of the module from `$env:PSModulePath` (typically
`$HOME/.local/share/powershell/Modules/F4keH0und` on macOS/Linux, or a user module path on Windows) and/or from the `ModuleAnalysisCache`, rather
than the freshly-pulled source in your local git checkout. Running `git pull` in your clone does
**not** update the installed copy.

**Fix:** Run the included `Reinstall-F4keH0und.ps1` script from the repository root:

```powershell
cd /path/to/F4keH0und
./Reinstall-F4keH0und.ps1 -PullLatest
```

The script will:
1. Unload every in-memory copy of the module from the current session.
2. Delete every installed copy from every directory in `$env:PSModulePath`.
3. Clear the PowerShell `ModuleAnalysisCache`.
4. Pull the latest source from `origin/main` (when `-PullLatest` is passed).
5. Reinstall the fresh copy to your user module path from `$env:PSModulePath`.
6. Import the module and verify that `-PreferRecycling` is available.

**Manual sanity checks** (if it still fails after running the script):

```powershell
# Which file is actually loaded?
(Get-Module F4keH0und).Path

# Confirm the parameter is present on the cmdlet
(Get-Command New-F4keH0undDecoy).Parameters['PreferRecycling']

# Hunt for any other F4keH0und manifests on disk
Get-ChildItem -Path $HOME -Filter F4keH0und.psd1 -Recurse -ErrorAction SilentlyContinue
```

If `(Get-Module F4keH0und).Path` points anywhere other than your freshly installed copy, delete
that location and re-run `Import-Module F4keH0und -Force`.

---

## 📚 Documentation

All project docs (except this root `README.md`) live in `Docs/`, and every code/behavior change must include corresponding documentation updates.

| Document | Description |
|----------|-------------|
| [README.md](README.md) | This file — overview, quick start, feature reference |
| [Docs/README.md](Docs/README.md) | Documentation index and documentation maintenance policy |
| [Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md) | Module internals, data-flow diagrams, design decisions, extension points |
| [Docs/EXAMPLES.md](Docs/EXAMPLES.md) | 10+ complete deployment scenarios with annotated commands |
| [Docs/LAST-GENERATION-ROADMAP.md](Docs/LAST-GENERATION-ROADMAP.md) | Detailed phased plan for interface, Entra parity, lifecycle controls, and new element types |
| [Docs/CONTRIBUTING.md](Docs/CONTRIBUTING.md) | How to fork, develop, test, and submit pull requests |

---

## ⚠️ Disclaimer

**This is a hobby project for educational and research purposes.** Making unauthorized changes to a production Active Directory environment can cause significant disruption. Use this tool responsibly and only on environments where you have explicit permission. The author is not responsible for any damage caused by the use or misuse of this software. Always test in a lab environment first.

---

## 📄 License

This project is licensed under the MIT License.
