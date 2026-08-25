# F4keH0und - Last Generation — Architecture

This document describes the internal architecture of F4keH0und - Last Generation, including module structure, data-flow diagrams, design decisions, and extension points for developers.

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
8. [Windows Artifact Plane (Phase 3)](#8-windows-artifact-plane-phase-3)

---

## 1. Philosophy: Recycling-First

F4keH0und - Last Generation is built around a single principle: **decoys that look real must be real**. The most detectable property of a newly created decoy is its RID (Relative Identifier) — a sequentially assigned number that immediately reveals when an object was added to the domain. An attacker who sorts all AD objects by SID can trivially identify every decoy created after a baseline date.

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
├── telemetry-connectors.windows.json       # SIEM/SOAR connector preset mappings for trigger ingestion
│
├── Public/                                 # Exported functions (user-facing API)
│   ├── Find-F4keH0undOpportunity.ps1       # Analysis engine — parses BH data, calls recycling engine
│   ├── New-F4keH0undDecoy.ps1              # Deployment orchestrator — calls Set-Private* helpers
│   ├── Get-F4keH0undElementType.ps1        # Lists Windows artifact element families/types from registry
│   ├── New-F4keH0undElement.ps1            # Windows artifact deployment command (WinRM/PSRP)
│   ├── New-F4keH0undToken.ps1              # Token-priority wrapper for identity/cloud credential bait profiles
│   ├── Register-F4keH0undTokenTrigger.ps1  # Trigger ingestion for token interactions and alert scoring
│   ├── Update-F4keH0undElement.ps1         # Windows artifact lifecycle update command
│   ├── Disable-F4keH0undElement.ps1        # Windows artifact lifecycle disable command
│   ├── Enable-F4keH0undElement.ps1         # Windows artifact lifecycle enable command
│   ├── Remove-F4keH0undElement.ps1         # Windows artifact lifecycle remove command
│   ├── Sync-F4keH0undEntraParity.ps1       # Entra parity remediation planner/executor
│   ├── Update-F4keH0undDecoy.ps1           # Lifecycle update command for decoy metadata/relationships
│   ├── Disable-F4keH0undDecoy.ps1          # Lifecycle state command — disable decoy identities
│   ├── Enable-F4keH0undDecoy.ps1           # Lifecycle state command — re-enable decoy identities
│   ├── Get-F4keH0undInventory.ps1          # Inventory interface — reads persistent events/reports and verifies live status
│   ├── Add-F4keH0undRelationship.ps1       # ACL relationship writer for ACLAttackPath decoys
│   ├── Remove-F4keH0undDecoy.ps1           # Lifecycle cleanup/removal command
│   ├── Test-F4keH0undDrift.ps1             # Phase 5 drift detector + redesign recommendation engine
│   └── Test-F4keH0undCoverage.ps1          # AD/Entra parity scoring and coverage matrix
│
└── Private/                                # Internal functions (not exported)
    ├── Find-F4keH0undRecyclableObject.ps1  # Recycling engine — staleness scoring and AD queries
    ├── Find-F4keH0undRecyclableEntraObject.ps1 # Recycling engine — stale Entra object discovery
    ├── Get-F4keH0undConfig.ps1             # Config reader — parses config.json with defaults
	    ├── Get-F4keH0undData.ps1               # BloodHound data loader — reads and normalizes JSON
	    ├── Get-F4keH0undElementTypeRegistry.ps1 # Loads/validates Windows element-type registry
	    ├── Get-F4keH0undRolloutProfile.ps1     # Phase 5 rollout-profile resolver and merge helper
	    ├── Get-F4keH0undParityModel.ps1        # Shared parity family/lifecycle capability model
    ├── Get-F4keH0undRank.ps1               # Opportunity ranker — Critical / High / Low assignment
	    ├── Manage-F4keH0undEntraLifecycle.ps1  # Entra lifecycle helpers (resolve/state/event context)
	    ├── Manage-F4keH0undInventory.ps1       # Persistent inventory event backend (NDJSON + snapshot)
	    ├── Manage-F4keH0undTelemetryConnector.ps1 # Telemetry connector pack loader + payload mapping helpers
	    ├── Manage-F4keH0undWindowsElement.ps1  # Windows artifact deployment + lifecycle execution plane
    ├── Set-PrivateADDecoyUser.ps1          # Recycles a stale user into a decoy
    ├── Set-PrivateADDecoyComputer.ps1      # Recycles a stale computer into a decoy
    ├── Set-PrivateADDecoyGroup.ps1         # Recycles a stale group into a decoy
    ├── Set-PrivateADDecoySPN.ps1           # Adds/removes SPNs on recycled users
    ├── Set-PrivateADACL.ps1                # Writes ACL entries for ACLAttackPath decoys
    ├── Set-PrivateEntraDecoyPrincipal.ps1  # Recycles stale Entra principals/apps into decoys
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
║              F4keH0und - Last Generation Architecture                     ║
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
      │ EntraServicePrincipalDecoy / EntraGuestUserDecoy / EntraAppRegistrationDecoy
      ▼
Set-PrivateEntraDecoyPrincipal (Microsoft Graph recycling)

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

### Manage-F4keH0undInventory (Private)

Implements persistent lifecycle inventory storage and state folding:
- Appends lifecycle events (`Deploy`, `Update`, `Disable`, `Enable`, `Remove`) to NDJSON.
- Reconstructs current inventory state from event history.
- Maintains an optional snapshot cache for fast inventory reads.

`New-F4keH0undDecoy`, `Update-F4keH0undDecoy`, `Disable-F4keH0undDecoy`, `Enable-F4keH0undDecoy`, and `Remove-F4keH0undDecoy` all write inventory events through this backend.

### Update/Disable/Enable Lifecycle Commands (Public)

These commands provide CRUD-like lifecycle operations for deployed AD and Entra decoys:
- `Update-F4keH0undDecoy` modifies AD descriptions/memberships/SPNs and Entra decoy description metadata.
- `Disable-F4keH0undDecoy` disables AD (`Disable-ADAccount`) or Entra (`AccountEnabled:$false`) identities.
- `Enable-F4keH0undDecoy` re-enables AD or Entra identities.
- `Remove-F4keH0undDecoy` deletes AD objects (membership-safe) and Entra objects (service principals, guest users, app registrations).

Every command records a persistent inventory event so `Get-F4keH0undInventory -Source Events` can reflect current lifecycle state without relying only on CSV deployment reports.

### Test-F4keH0undCoverage / Sync-F4keH0undEntraParity (Public)

These Phase 2 parity commands operationalize AD-vs-Entra coverage management:
- `Test-F4keH0undCoverage` builds a capability matrix and family-level gap report from inventory state.
- `Sync-F4keH0undEntraParity` maps those gaps to Entra opportunities and can deploy recyclable Entra decoys to reduce drift.

Entra opportunity templates now include themed lure metadata for:

- role-assignment reconnaissance bait,
- OAuth consent scope traps,
- conditional-access bypass hinting,
- stale secret/certificate lure context.

This metadata is carried through deployment planning and inventory event metadata to keep analyst triage context close to each deployed Entra decoy.

Both commands use `Get-F4keH0undParityModel` for deterministic family mapping and lifecycle scoring.

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

## 8. Windows Artifact Plane (Phase 3)

Phase 3 introduces a dedicated Windows-only artifact execution plane while preserving a cross-platform operator experience (`pwsh` on macOS/Linux/Windows).

### 8.1 Operating Model

- **Control plane:** cross-platform PowerShell module execution.
- **Target plane:** Windows hosts only.
- **Deployment channel:** WinRM/PSRP first.
- **Default behavior:** artifact-only (no active listener services).
- **Telemetry baseline:** Sysmon + Windows Security logs.

### 8.2 Element Type Registry

- External registry file: `element-types.windows.json`.
- Runtime loader: `Private/Get-F4keH0undElementTypeRegistry.ps1`.
- Public discovery command: `Get-F4keH0undElementType`.
- Supported initial families:
  - `ServiceLure` (`ServiceDefinitionDecoy`)
  - `RpcBait` (`RpcEndpointDecoy`)
  - `ApiHookBait` (`ApiHookConfigDecoy`)
  - `RuntimeArtifact` (`ProcessThreadArtifactDecoy`)
  - `IdentityTokenBait` (`IdentityBreadcrumbTokenDecoy`)
  - `CloudTokenBait` (`CloudApiCanaryTokenDecoy`)
  - `CredentialBait` (`CredentialFileTokenDecoy`)

### 8.3 Lifecycle Command Surface

Windows artifact lifecycle is fully represented with dedicated commands:

- `New-F4keH0undElement`
- `New-F4keH0undToken`
- `Register-F4keH0undTokenTrigger`
- `Update-F4keH0undElement`
- `Disable-F4keH0undElement`
- `Enable-F4keH0undElement`
- `Remove-F4keH0undElement`

Internally, lifecycle actions route through `Invoke-PrivateF4keH0undWindowsElementLifecycle`, which:

1. Resolves type + metadata context.
2. Renders artifacts from template data.
3. Executes remote writes via WinRM/PSRP.
4. Emits persistent inventory events with `Platform = Windows`.

### 8.4 Configuration Additions

Phase 3 extends configuration with:

- `WindowsDeploymentSettings` — WinRM defaults, artifact root, throttle settings.
- `TelemetrySettings` — default telemetry profile + source hints.
- `TelemetrySettings.ConnectorPackPath` — telemetry connector preset pack path for SIEM/SOAR payload mapping.
- `ElementRegistrySettings` — registry path + fallback behavior.
- `RolloutProfiles` — Phase 5 rollout defaults (`Lab`, `Pilot`, `Production`) for WhatIf/throttle/deployment-cap behavior.

These are present in both `config.json` and `config.example.json`, validated by `Test-F4keH0undConfig`, and consumed by lifecycle commands.

### 8.5 Inventory Integration

`Get-F4keH0undInventory` now supports cross-platform inventory filters that work for AD, Entra, and Windows elements:

- `-Platform`
- `-ElementType`
- `-ElementFamily`
- `-ComputerName`
- `-Status`

This forms the first implementation of the requested unified interface for where deceptive elements are deployed and what lifecycle state they are in.

### 8.6 Opportunity-Ranking Integration

`Find-F4keH0undOpportunity` in AD mode now accepts explicit Windows targets (`-WindowsComputerName`) and appends ranked Windows artifact opportunities (`Strategy = Artifact`) to the returned queue.

- Ranking combines `DetectionScore`, `CostScore`, and `RiskLevel` from the element registry.
- Identity/token/credential families receive additional prioritization weight.
- Returned opportunities include deployment hints (`RecommendedCommand = New-F4keH0undElement`) and explicit host targeting metadata.

This closes the Phase 3 ranking-integration gap and creates a direct bridge into Phase 4 token-priority operations.

### 8.7 Token Trigger Correlation and Alert Scoring

Inventory now supports first-class trigger telemetry correlation for token/identity deception:

- `Write-F4keH0undInventoryEvent` accepts `Action = Trigger`.
- `Register-F4keH0undTokenTrigger` writes trigger events from SIEM/SOAR pipelines.
- State model tracks trigger fields (`TriggerCount`, `LastTriggeredAt`, `TokenCorrelationStatus`).
- Alert model computes per-element severity outputs (`AlertScore`, `AlertSeverity`, `AlertReasons`).

Correlation behavior:

1. Token indicators are fingerprinted (`sha256:<short>`) from stored metadata/template fields.
2. Incoming trigger token identifiers are normalized to the same fingerprint format.
3. Match/mismatch drives `TokenCorrelationStatus` (`Correlated`, `Uncorrelated`, `Unknown`).

Alert scoring behavior:

- Score combines signal count, repeat triggers, confidence, decoy family priority, and correlation status.
- Severity mapping: `None` (0), `Low`, `Medium`, `High`, `Critical`.
- `Get-F4keH0undInventory` supports alert filtering via `-AlertSeverity` and `-MinAlertScore`.

### 8.8 Telemetry Connector Pack

Phase 4 adds preset-based telemetry normalization so SIEM/SOAR events can feed directly into trigger registration.

- Connector pack file: `telemetry-connectors.windows.json`.
- Loader and mapping helpers: `Private/Manage-F4keH0undTelemetryConnector.ps1`.
- Trigger ingestion command: `Register-F4keH0undTokenTrigger -ConnectorPreset <PresetId> -TelemetryPayload <Object>`.

Default preset set:

- `SysmonEvent11FileCreate`
- `SysmonEvent3NetworkConnect`
- `WindowsSecurity4624Logon`
- `WindowsSecurity4663ObjectAccess`
- `WindowsSecurity4688ProcessCreate`

Connector behavior:

1. Load preset mapping from `TelemetrySettings.ConnectorPackPath` (with built-in fallback).
2. Resolve identity/actor/host/evidence/token fields from mapped payload keys.
3. Apply preset defaults for `TriggerType`, `TriggerSource`, `SignalCount`, and `Confidence`.
4. Emit trigger event metadata with `ConnectorPreset` for downstream analysis.

### 8.9 Phase 5 Rollout Profiles

Phase 5 introduces profile-driven operational guardrails through `RolloutProfiles` config and `Get-PrivateF4keH0undRolloutProfile`.

Current command integration:

- `New-F4keH0undElement` and `New-F4keH0undToken` consume profile defaults for rollout throttle and optional WhatIf-by-default behavior.
- `Sync-F4keH0undEntraParity` consumes profile defaults for `MaxDeployments`, optional WhatIf-by-default, and role-assignment suppression.
- `New-F4keH0undDecoy` applies profile guardrails for Entra deployment count and high-privilege role-assignment handling.

### 8.10 Phase 5 Drift Checks

`Test-F4keH0undDrift` adds lightweight operations hardening for stale deceptive artifacts and token lures.

Current behavior:

- Reads inventory (`Auto`/`Events`/`Reports`) and defaults to lightweight mode (`SkipLiveStatus = true`) unless explicitly overridden.
- Scores per-element drift using lifecycle age, trigger recurrence, alert severity, and metadata completeness checks.
- Prioritizes identity/token families by applying stricter staleness thresholds and canary-presence checks.
- Produces actionable redesign guidance (`RecommendedAction`, `SuggestedCommand`) for Windows, AD, and Entra element refresh workflows.

### 8.11 Phase 5 Response Playbooks

Phase 5 response operations add a reusable playbook layer for token-trigger incidents.

Components:

- `Docs/RESPONSE-PLAYBOOKS.md` provides canonical High/Critical incident templates.
- `scripts/New-TokenTriggerResponsePlaybook.ps1` generates incident-specific markdown playbooks from inventory context.
- Generated playbooks can enrich findings with drift-driven redesign recommendations (`Test-F4keH0undDrift`).

---

## See Also

- [README.md](../README.md) — Overview, quick start, and feature reference
- [EXAMPLES.md](EXAMPLES.md) — Complete deployment scenarios
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
