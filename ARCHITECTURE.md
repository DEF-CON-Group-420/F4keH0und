# F4keH0und — Architecture

This document describes the internal architecture of F4keH0und v2.0, including module structure, data-flow diagrams, design decisions, and extension points for developers.

---

## Contents

1. [Philosophy: Recycling-First](#1-philosophy-recycling-first)
2. [Module Structure](#2-module-structure)
3. [System Architecture Diagram](#3-system-architecture-diagram)
4. [Data Flow Diagrams](#4-data-flow-diagrams)
   - [Analysis Flow](#41-analysis-flow)
   - [Recycling Engine Flow](#42-recycling-engine-flow)
   - [Deployment Flow](#43-deployment-flow)
5. [Key Components](#5-key-components)
6. [Design Decisions](#6-design-decisions)
7. [Extension Points](#7-extension-points)

---

## 1. Philosophy: Recycling-First

F4keH0und v2.0 is built around a single principle: **decoys that look real must be real**. The most detectable property of a newly created decoy is its RID (Relative Identifier) — a sequentially assigned number that immediately reveals when an object was added to the domain. An attacker who sorts all AD objects by SID can trivially identify every decoy created after a baseline date.

The solution is to never create new objects when a suitable stale object already exists. By modifying a disabled account that has existed in the domain for years, the decoy inherits the original RID, `whenCreated` timestamp, and the entire history of that object — making it indistinguishable from a legitimate dormant account.

The v2.0 architecture operationalizes this philosophy with:

- A dedicated recycling engine (`Find-F4keH0undRecyclableObject`) with multi-dimensional staleness scoring.
- A recycling-first priority order in the analysis pipeline.
- Safety filters that prevent accidental recycling of sensitive or active objects.
- Rank boosts for recycling opportunities so they appear first in results.

---

## 2. Module Structure

```
F4keH0und/
├── F4keH0und.psd1                          # Module manifest (exports, version, metadata)
├── F4keH0und.psm1                          # Module root — dot-sources all Public and Private scripts
├── config.json                             # Active configuration (read at runtime)
├── config.example.json                     # Template for new deployments
│
├── Public/                                 # Exported functions (user-facing API)
│   ├── Find-F4keH0undOpportunity.ps1       # Analysis engine — parses BH data, calls recycling engine
│   ├── New-F4keH0undDecoy.ps1              # Deployment orchestrator — calls Set-Private* helpers
│   ├── Add-F4keH0undRelationship.ps1       # ACL relationship writer for ACLAttackPath decoys
│   └── Remove-F4keH0undDecoy.ps1           # Cleanup — reverses all changes made by New-F4keH0undDecoy
│
└── Private/                                # Internal functions (not exported)
    ├── Find-F4keH0undRecyclableObject.ps1  # Recycling engine — staleness scoring and AD queries
    ├── Get-F4keH0undConfig.ps1             # Config reader — parses config.json with defaults
    ├── Get-F4keH0undData.ps1               # BloodHound data loader — reads and normalizes JSON
    ├── Get-F4keH0undRank.ps1               # Opportunity ranker — Critical / High / Low assignment
    ├── Set-PrivateADDecoyUser.ps1          # Recycles a stale user into a decoy
    ├── Set-PrivateADDecoyComputer.ps1      # Recycles a stale computer into a decoy
    ├── Set-PrivateADDecoyGroup.ps1         # Recycles a stale group into a decoy
    ├── Set-PrivateADDecoySPN.ps1           # Adds/removes SPNs on recycled users
    ├── Set-PrivateADACL.ps1                # Writes ACL entries for ACLAttackPath decoys
    └── Test-F4keH0undConfig.ps1            # Configuration validator
```

**Deprecated (not loaded):**
```
Private/New-PrivateADDecoyComputer.ps1.deprecated   # v1.x — created new objects (now replaced by Set-* recyclers)
Private/New-PrivateADDecoyGroup.ps1.deprecated      # v1.x — created new objects
Private/New-PrivateADDecoyUser.ps1.deprecated       # v1.x — created new objects
```

The `.deprecated` files are retained for historical reference and are explicitly excluded from the module loader in `F4keH0und.psm1`.

---

## 3. System Architecture Diagram

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                         F4keH0und v2.0 Architecture                       ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────────┐ ║
║  │  INPUT LAYER    │   │  ANALYSIS LAYER │   │  EXECUTION LAYER        │ ║
║  ├─────────────────┤   ├─────────────────┤   ├─────────────────────────┤ ║
║  │                 │   │                 │   │                         │ ║
║  │  SharpHound     │──▶│ Find-Opportunity│   │  New-F4keH0undDecoy     │ ║
║  │  JSON files     │   │                 │   │                         │ ║
║  │  (BloodHound)   │   │  ┌───────────┐  │   │  ┌─────────────────┐   │ ║
║  │                 │   │  │ Get-Data  │  │   │  │ Set-DecoyUser   │   │ ║
║  │  AzureHound     │──▶│  │ (loader)  │  │   │  │ (recycles user) │   │ ║
║  │  JSON files     │   │  └───────────┘  │   │  └─────────────────┘   │ ║
║  │                 │   │                 │   │  ┌─────────────────┐   │ ║
║  │  config.json    │──▶│  ┌───────────┐  │   │  │ Set-DecoyComp.  │   │ ║
║  │  (settings)     │   │  │ Get-Rank  │  │   │  │ (recycles comp) │   │ ║
║  └─────────────────┘   │  └───────────┘  │   │  └─────────────────┘   │ ║
║                        │                 │   │  ┌─────────────────┐   │ ║
║                        │  ┌───────────┐  │   │  │ Set-DecoyGroup  │   │ ║
║                        │  │ Find-Recy-│  │──▶│  │ (recycles group)│   │ ║
║                        │  │ clable    │  │   │  └─────────────────┘   │ ║
║                        │  │ Object    │  │   │  ┌─────────────────┐   │ ║
║                        │  └───────────┘  │   │  │ Set-DecoySPN    │   │ ║
║                        └─────────────────┘   │  │ (adds SPN)      │   │ ║
║                                              │  └─────────────────┘   │ ║
║                                              │  ┌─────────────────┐   │ ║
║                                              │  │ Set-ACL         │   │ ║
║                                              │  │ (ACL path)      │   │ ║
║                                              │  └─────────────────┘   │ ║
║                                              └──────────┬──────────────┘ ║
║                                                         │               ║
║  ┌──────────────────────────────────────────────────────▼─────────────┐ ║
║  │                  Active Directory / Entra ID                        │ ║
║  │                                                                     │ ║
║  │   Disabled user     Stale computer    Empty group                   │ ║
║  │   (recycled)        (recycled)        (recycled)                    │ ║
║  │   RID: original     RID: original     RID: original                 │ ║
║  │   Created: 2019     Created: 2018     Created: 2020                 │ ║
║  └─────────────────────────────────────────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 4. Data Flow Diagrams

### 4.1 Analysis Flow

```
User calls Find-F4keH0undOpportunity
             │
             ▼
    ┌─────────────────┐
    │ Get-F4keH0und   │  Reads config.json — RecyclingPreferences, SafetyFilters
    │ Config          │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Get-F4keH0und   │  Loads and normalizes SharpHound / AzureHound JSON files
    │ Data            │  Handles both timestamp-prefixed (SharpHound) and
    └────────┬────────┘  single-file (AzureHound) formats
             │
             ├─────────────────────────────────┐
             │ (AD mode only)                  │ (Azure mode)
             ▼                                 ▼
    ┌─────────────────┐             ┌─────────────────┐
    │ Find-F4keH0und  │             │  Entra ID        │
    │ RecyclableObject│             │  Analysis        │
    │                 │             │  (PrivilegedSP   │
    │  Queries AD for │             │   opportunities) │
    │  disabled/stale │             └────────┬─────────┘
    │  Users,         │                      │
    │  Computers,     │                      │
    │  Groups         │                      │
    │                 │                      │
    │  Scores each    │                      │
    │  with Staleness │                      │
    │  Score (0-100)  │                      │
    └────────┬────────┘                      │
             │                               │
             ▼                               │
    ┌─────────────────┐                      │
    │  BH Data        │                      │
    │  Analysis       │                      │
    │                 │                      │
    │  Identifies:    │                      │
    │  - Stale admins │                      │
    │  - SPN targets  │                      │
    │  - Delegation   │                      │
    │  - DnsAdmins    │                      │
    │  - ACL paths    │                      │
    └────────┬────────┘                      │
             │                               │
             ▼                               │
    ┌─────────────────┐                      │
    │ Get-F4keH0und   │◀─────────────────────┘
    │ Rank            │
    │                 │
    │  Assigns:       │
    │  Critical /     │
    │  High / Low     │
    │                 │
    │  Recycle gets   │
    │  rank boost     │
    └────────┬────────┘
             │
             ▼
    Returns ranked List[PSObject]
    (opportunities sorted by Rank + StalenessScore)
```

### 4.2 Recycling Engine Flow

```
Find-F4keH0undRecyclableObject -Type User
             │
             ▼
    ┌─────────────────┐
    │ Load config     │  MinimumObjectAgeDays, MaximumObjectAgeDays,
    │ defaults        │  ExcludedOUs, ProtectedUserPatterns
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Get-ADUser      │  Filter: Enabled -eq $false
    │ (AD query)      │  Properties: SamAccountName, whenCreated,
    └────────┬────────┘             PasswordLastSet, MemberOf, SID, ...
             │
             ▼ Filter pipeline (each step reduces the candidate set)
    ┌─────────────────┐
    │ Age window      │  whenCreated between MinAge and MaxAge thresholds
    │ filter          │
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ PasswordLastSet │  Must be older than MinimumPasswordAgeDays
    │ filter          │
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ Active keywords │  Skip if Description contains: service, production,
    │ filter          │  critical, backup
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ Protected       │  Skip if SamAccountName matches any
    │ pattern filter  │  ProtectedUserPatterns regex
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ Privileged      │  Skip if MemberOf contains any PrivilegedGroupNames
    │ group filter    │  (Domain Admins, Enterprise Admins, ...)
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ OU exclusion    │  Skip if DistinguishedName matches any ExcludedOUs
    │ filter          │  pattern (wildcard matching)
    └────────┬────────┘
             ▼
    ┌─────────────────┐
    │ Staleness       │  Score 0-100 based on:
    │ scoring         │    Age (DaysSinceCreation)           0.4 weight
    │                 │    Inactivity (PasswordLastSet age)  0.3 weight
    │                 │    Group isolation (no MemberOf)     0.2 weight
    │                 │    Empty description                 0.1 weight
    └────────┬────────┘
             │
             ▼
    Return sorted by StalenessScore DESC, limited to MaxResults
```

### 4.3 Deployment Flow

```
User calls New-F4keH0undDecoy -Execute
             │
             ▼
    ┌─────────────────┐
    │ Find-Opportunity│  (same analysis flow as above)
    │ (internal call) │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Interactive     │  Present ranked opportunities to user
    │ selection UI    │  User selects which to deploy (or -Force skips)
    └────────┬────────┘
             │
             ▼
    For each selected opportunity:
    ┌─────────────────┐
    │ switch          │
    │ (DecoyType)     │
    └────────┬────────┘
             │
      ┌──────┼──────────────────────────────────┐
      │      │                                  │
      ▼      ▼                                  ▼
StaleAdmin  KerberoastableUser          UnconstrainedDelegation
DNSAdmin    │                           │
    │       ▼                           ▼
    │  Set-PrivateADDecoyUser    Set-PrivateADDecoyComputer
    │  + Set-PrivateADDecoySPN   (sets TrustedForDelegation)
    │
    ▼
Set-PrivateADDecoyUser
(+ Add-ADGroupMember for DnsAdmins)

      ┌──────────────────┐
      │ ACLAttackPath    │
      ▼                  │
Add-F4keH0undRelationship│
(Set-PrivateADACL)       │
                         │
      ┌──────────────────┘
      │ PrivilegedEntraSP
      ▼
Entra ID SP creation (via Microsoft Graph)

             │ (all paths converge)
             ▼
    ┌─────────────────┐
    │ Generate CSV    │  Writes deployment report to ReportOutputPath
    │ report          │
    └─────────────────┘
```

---

## 5. Key Components

### Find-F4keH0undOpportunity (Public)

The analysis engine. Orchestrates the full pipeline:
1. Loads configuration.
2. Calls `Get-F4keH0undData` to parse BloodHound JSON.
3. If in AD mode, calls `Find-F4keH0undRecyclableObject` for User, Computer, and Group types.
4. Merges recycling results with BloodHound-derived opportunities.
5. Assigns ranks via `Get-F4keH0undRank` — recycling candidates get a rank boost.
6. Returns a sorted `List[PSObject]` with full opportunity metadata.

**Key parameters:** `-PreferRecycling`, `-RecyclingOnly`, `-RecyclingMinimumAgeDays`, `-ExcludeOUs`

### Find-F4keH0undRecyclableObject (Private)

The recycling engine. The heart of the v2.0 architecture:
- Queries AD for disabled/stale objects (User, Computer, or Group).
- Applies a multi-stage filter pipeline to eliminate unsafe candidates.
- Scores remaining candidates with a `StalenessScore` (0–100).
- Returns candidates sorted by score descending, capped at `MaxResults`.

**Staleness scoring weights (configurable via RankingWeights):**

| Factor | Weight | Description |
|--------|--------|-------------|
| `StalenessScoreWeight` | 0.4 | Object age relative to age window |
| `PrivilegedGroupProximityWeight` | 0.3 | How close the object was to privileged groups (inverse) |
| `IsolationWeight` | 0.2 | Whether the object has no group memberships |
| `AgeWeight` | 0.1 | Raw days since creation |

### Set-PrivateADDecoyUser / Computer / Group (Private)

The modification workers. Each follows the same safety-then-modify pattern:
1. Re-validate that the object is still safe to recycle (re-checks all safety filters).
2. If `-WhatIf`, emit a `ShouldProcess` message and return without modifying.
3. Apply the transformation (set description, reset password, add SPN, set delegation flag, etc.).
4. Log the original attribute values for later reversal by `Remove-F4keH0undDecoy`.

**Critical: these functions never delete or create objects.** They only modify existing ones.

### Get-F4keH0undConfig (Private)

Reads and merges `config.json` with built-in defaults. Every consumer calls this at the start of execution, so changing `config.json` takes effect on the next run without re-importing the module.

### Test-F4keH0undConfig (Public/Private)

Validates all configuration keys, checks regex patterns for syntax errors, verifies OU paths are well-formed, and confirms that MinimumObjectAgeDays < MaximumObjectAgeDays. Returns `$true` on success.

---

## 6. Design Decisions

### Why "Set-" instead of "New-" for the private helpers?

The v1.x helpers were named `New-PrivateADDecoy*` because they created new objects. The v2.0 helpers are named `Set-PrivateADDecoy*` to reflect the shift: they **set** properties on existing objects rather than creating new ones. The `.deprecated` suffix on the old files makes the transition explicit.

### Why is staleness scoring additive (0–100) rather than boolean pass/fail?

A boolean filter would either accept or reject candidates. The additive scoring system allows the engine to rank dozens of candidates and surface the best ones first. A computer object that is 8 years old, has never had its password reset, and has no group memberships is a far better recycling candidate than one that is 6 months old — the scoring captures this nuance.

### Why are ProtectedUserPatterns stored as regex rather than exact strings?

Production AD environments often have systematic naming conventions (e.g., all service accounts start with `svc_prod_`). Regex patterns let administrators protect entire categories of accounts with a single rule rather than maintaining a growing list of exact names.

### Why does Find-F4keH0undOpportunity call the recycling engine internally rather than requiring the user to call it separately?

Convenience and atomicity. The user should not need to know that a recycling engine exists — they call `Find-F4keH0undOpportunity` and get the best opportunities regardless of whether they come from recycling or creation. The `-PreferRecycling` and `-RecyclingOnly` flags give advanced users control without exposing the engine unnecessarily.

### Why is config read from a JSON file rather than module-level variables?

JSON config files are easy to version-control, diff, audit, and deploy via configuration management tools (Ansible, DSC, GPO). Module-level variables would require re-importing the module after every change and make auditing harder.

---

## 7. Extension Points

### Adding a New Decoy Type

Follow these four steps to add a new decoy type to the pipeline:

**Step 1: Define the opportunity detection logic**

In `Public\Find-F4keH0undOpportunity.ps1`, add a new block inside the BloodHound analysis section. The block should:
- Query the BloodHound JSON data for objects matching your criteria.
- Optionally call `Find-F4keH0undRecyclableObject` to find a suitable stale object to recycle.
- Emit a `[PSCustomObject]` with at minimum: `DecoyType`, `Identity`, `Source` (`Recycle` or `Create`), and any type-specific fields.

```powershell
# Example: Detect accounts with AdminSDHolder propagation
$adminSdHolderAccounts = $bhUsers | Where-Object { $_.Properties.admincount -eq 1 }
foreach ($account in $adminSdHolderAccounts) {
    [PSCustomObject]@{
        DecoyType  = "AdminSDHolderLure"
        Identity   = $account.Properties.distinguishedname
        Source     = "Recycle"
        Confidence = "High"
    }
}
```

**Step 2: Add ranking logic**

In `Private\Get-F4keH0undRank.ps1`, add a new case to the `switch` statement:

```powershell
"AdminSDHolderLure" {
    return "High"
}
```

**Step 3: Add deployment logic**

In `Public\New-F4keH0undDecoy.ps1`, add a new case to the deployment `switch` statement:

```powershell
"AdminSDHolderLure" {
    Set-PrivateADDecoyAdminSDHolder -ExistingUser $opportunity.Identity `
        -Description "Legacy Helpdesk Admin Account" `
        @adParams
}
```

**Step 4: Create the private helper**

Create `Private\Set-PrivateADDecoyAdminSDHolder.ps1` following the same pattern as the existing `Set-PrivateADDecoy*.ps1` files:
- Accept `[CmdletBinding(SupportsShouldProcess)]`.
- Re-validate safety before modifying.
- Log original attribute values.
- Apply the transformation.
- Return a result object.

### Adding a New Staleness Score Factor

To add a new factor to the staleness scoring formula in `Find-F4keH0undRecyclableObject`:

1. Add the factor's computation to the scoring block in `Find-F4keH0undRecyclableObject.ps1`.
2. Add a corresponding weight key to the `RankingWeights` section of `config.json` and `config.example.json`.
3. Read the weight in `Find-F4keH0undRecyclableObject.ps1` via `Get-F4keH0undConfig -Section RankingWeights`.

### Adding a New Safety Filter

To add a new hard exclusion rule:

1. Add the filter's configuration key to the `SafetyFilters` section of `config.json` and `config.example.json`.
2. In `Find-F4keH0undRecyclableObject.ps1`, read the new key from `$safetyConfig` and add a new `Where-Object` filter step in the filter pipeline.
3. Add validation for the new key in `Test-F4keH0undConfig.ps1`.

---

## See Also

- [README.md](README.md) — Overview, quick start, and feature reference
- [EXAMPLES.md](EXAMPLES.md) — Complete deployment scenarios
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
