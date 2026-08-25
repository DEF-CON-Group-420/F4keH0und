# Command Reference

This document describes every exported `F4keH0und` module command, its parameters, expected behavior, and practical usage patterns.

Coverage of command sections in this file is enforced in CI by `scripts/Test-CommandReferenceCoverage.ps1`.

## Command Inventory

Current exported commands:

1. `Find-F4keH0undOpportunity`
2. `New-F4keH0undDecoy`
3. `Sync-F4keH0undEntraParity`
4. `Update-F4keH0undDecoy`
5. `Disable-F4keH0undDecoy`
6. `Enable-F4keH0undDecoy`
7. `Get-F4keH0undInventory`
8. `Add-F4keH0undRelationship`
9. `Remove-F4keH0undDecoy`
10. `Get-F4keH0undConfig`
11. `Test-F4keH0undCoverage`
12. `Test-F4keH0undConfig`

---

## Common PowerShell Behavior

- All exported commands support standard common parameters (`-Verbose`, `-Debug`, `-ErrorAction`, etc.).
- The following commands support `-WhatIf`/`-Confirm` (safe simulation via `ShouldProcess`):
  - `New-F4keH0undDecoy`
  - `Sync-F4keH0undEntraParity`
  - `Update-F4keH0undDecoy`
  - `Disable-F4keH0undDecoy`
  - `Enable-F4keH0undDecoy`
  - `Add-F4keH0undRelationship`
  - `Remove-F4keH0undDecoy`
- AD-backed commands typically accept `-Server` and `-Credential` for cross-domain/bastion operations.

---

## `Find-F4keH0undOpportunity`

Analyzes BloodHound/AzureHound data and returns ranked deception opportunities.

### Modes

- **AD mode**: use `-BloodHoundPath`
- **Entra mode**: use `-AzureHoundPath`

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `BloodHoundPath` | `String` | AD mode | — | Path to SharpHound/BloodHound AD JSON directory. |
| `AzureHoundPath` | `String` | Entra mode | — | Path to AzureHound JSON directory. |
| `StaleAdminThresholdDays` | `Int32` | No | `365` | Threshold for stale privileged-account analysis. |
| `PreferRecycling` | `Switch` | No | `false` | Prioritizes recycling opportunities in AD mode. |
| `RecyclingOnly` | `Switch` | No | `false` | Returns only recycling opportunities in AD mode. |
| `RecyclingMinimumAgeDays` | `Int32` | No | `180` | Minimum age for recyclable AD objects. |
| `RecyclingMaximumAgeDays` | `Int32` | No | `3650` | Maximum age for recyclable AD objects. |
| `ExcludeOUs` | `String[]` | No | from config | Excludes OUs from AD recycling candidate search. |
| `Server` | `String` | No | — | Domain Controller for AD lookups. |
| `Credential` | `PSCredential` | No | — | Credentials for AD lookups. |
| `EntraIncludeServicePrincipals` | `Switch` | No | auto-all | Include disabled service principals in Entra scan. |
| `EntraIncludeGuestUsers` | `Switch` | No | auto-all | Include inactive guest users in Entra scan. |
| `EntraIncludeAppRegistrations` | `Switch` | No | auto-all | Include unused app registrations in Entra scan. |
| `EntraRecyclingMinimumAgeDays` | `Int32` | No | `180` | Minimum age for recyclable Entra objects. |
| `EntraRecyclingMaximumAgeDays` | `Int32` | No | `3650` | Maximum age for recyclable Entra objects. |
| `EntraPreferRecycling` | `Switch` | No | `false` | Boosts Entra recycling opportunity rank. |
| `EntraRecyclingOnly` | `Switch` | No | `false` | Returns only Entra recycling opportunities. |

### Output

Returns a collection of opportunity objects with fields such as `ID`, `Rank`, `DecoyType`, `Strategy`, `Justification`, and `Template`.

### Example

```powershell
Find-F4keH0undOpportunity -BloodHoundPath ./BH_Data -PreferRecycling -Verbose
```

---

## `New-F4keH0undDecoy`

Runs analysis + interactive deployment workflow and deploys selected decoys.

### Modes

- **AD mode**: `-BloodHoundPath`
- **Entra mode**: `-AzureHoundPath`

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `BloodHoundPath` | `String` | AD mode | — | AD collector data path for analysis/deployment. |
| `AzureHoundPath` | `String` | Entra mode | — | Entra collector data path for analysis/deployment. |
| `Execute` | `Switch` | No | `false` | Starts interactive deployment; without it only analysis preview runs. |
| `PreferRecycling` | `Switch` | No | `false` | AD mode: prefer recycling opportunities. |
| `RecyclingOnly` | `Switch` | No | `false` | AD mode: deploy only recyclable opportunities. |
| `RecyclingMinimumAgeDays` | `Int32` | No | `180` | AD recycle minimum age filter. |
| `RecyclingMaximumAgeDays` | `Int32` | No | `3650` | AD recycle maximum age filter. |
| `ExcludeOUs` | `String[]` | No | from config | OU exclusions for recycle candidate discovery. |
| `DecoyPrefix` | `String` | No | from config | Prefix for newly created (non-recycled) object names. |
| `DecoySuffix` | `String` | No | from config | Suffix for newly created object names. |
| `AuditLogPath` | `String` | No | — | NDJSON audit log destination for recycling operations. |
| `Server` | `String` | No | — | Domain Controller for AD operations. |
| `Credential` | `PSCredential` | No | — | Credentials for AD operations. |

### Behavior Notes

- Uses `Find-F4keH0undOpportunity` internally.
- Displays opportunity list and prompts for IDs to deploy when `-Execute` is supplied.
- Deploys Entra recycling opportunities (`EntraServicePrincipalDecoy`, `EntraGuestUserDecoy`, `EntraAppRegistrationDecoy`) via `Set-PrivateEntraDecoyPrincipal`.
- Generates deployment report data and optional CSV handover.
- Writes lifecycle inventory `Deploy` events to persistent backend with platform-aware identity/location fields.

### Example

```powershell
New-F4keH0undDecoy -BloodHoundPath ./BH_Data -Execute -PreferRecycling -WhatIf
```

---

## `Sync-F4keH0undEntraParity`

Plans or applies Entra deployments to close family-level parity gaps against AD decoys.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `AzureHoundPath` | `String` | Yes | — | Path to AzureHound data for Entra opportunity discovery. |
| `Source` | `String` | No | `Auto` | Inventory source used for parity baseline (`Auto`, `Events`, `Reports`). |
| `IncludeRemoved` | `Switch` | No | `false` | Includes removed entries in parity baseline. |
| `PreferSnapshot` | `Switch` | No | `false` | Events source: prefer snapshot before event replay. |
| `SkipLiveStatus` | `Switch` | No | `false` | Skip AD live verification during parity baseline. |
| `Server` | `String` | No | — | Domain Controller for AD live status checks. |
| `Credential` | `PSCredential` | No | — | Credentials for AD live status checks. |
| `TargetParityRatio` | `Double` | No | `1.0` | Required Entra-to-AD ratio per mapped family. |
| `MaxDeployments` | `Int32` | No | `5` | Maximum Entra deployments for one execution run. |
| `Execute` | `Switch` | No | `false` | Applies recommended Entra deployments when set. |
| `AuditLogPath` | `String` | No | — | Optional audit log destination for recycled Entra operations. |
| `EntraIncludeServicePrincipals` | `Switch` | No | auto-all | Restrict discovery to service-principal opportunities. |
| `EntraIncludeGuestUsers` | `Switch` | No | auto-all | Restrict discovery to guest-user opportunities. |
| `EntraIncludeAppRegistrations` | `Switch` | No | auto-all | Restrict discovery to app-registration opportunities. |
| `EntraRecyclingMinimumAgeDays` | `Int32` | No | `180` | Minimum recyclable age filter for Entra objects. |
| `EntraRecyclingMaximumAgeDays` | `Int32` | No | `3650` | Maximum recyclable age filter for Entra objects. |
| `EntraPreferRecycling` | `Switch` | No | `false` | Boost rank for Entra recycling opportunities. |
| `EntraRecyclingOnly` | `Switch` | No | `false` | Limit Entra analysis to recyclable opportunities only. |
| `PassThru` | `Switch` | No | `false` | In execute mode, returns deployed object records. |

### Behavior Notes

- Uses `Test-F4keH0undCoverage` to measure current family-level gaps.
- Selects Entra opportunities that map to uncovered parity families first.
- In `-Execute` mode, deploys with `Set-PrivateEntraDecoyPrincipal` and writes inventory `Deploy` events.
- Returns before/after coverage state, planned opportunities, and deployment outcomes.

### Example

```powershell
Sync-F4keH0undEntraParity -AzureHoundPath ./AzureHound_Data -TargetParityRatio 1.0
Sync-F4keH0undEntraParity -AzureHoundPath ./AzureHound_Data -Execute -MaxDeployments 3 -WhatIf
```

---

## `Update-F4keH0undDecoy`

Applies lifecycle-safe updates to AD or Entra decoys.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Identity` | `String` | Yes | — | Target decoy object identity. |
| `Platform` | `String` | No | `AD` | Target platform: `AD` or `Entra`. |
| `ObjectType` | `String` | No | `User` | AD: `User`, `Computer`, `Group`; Entra: `ServicePrincipal`, `GuestUser`, `AppRegistration`. |
| `DecoyType` | `String` | No | `LifecycleManagedDecoy` | Decoy classification label for lifecycle events. |
| `Description` | `String` | No | — | Replaces object description. |
| `AddGroups` | `String[]` | No | — | Adds object to listed groups (AD mode). |
| `RemoveGroups` | `String[]` | No | — | Removes object from listed groups (AD mode). |
| `AddServicePrincipalNames` | `String[]` | No | — | Adds SPNs (AD User/Computer only). |
| `RemoveServicePrincipalNames` | `String[]` | No | — | Removes SPNs (AD User/Computer only). |
| `Server` | `String` | No | — | Domain Controller for AD operations (AD mode). |
| `Credential` | `PSCredential` | No | — | Credentials for AD operations (AD mode). |
| `PassThru` | `Switch` | No | `false` | Returns updated object. |

### Behavior Notes

- AD mode supports description, group membership, and SPN updates.
- Entra mode supports decoy-description updates (`Notes` or `JobTitle` depending on object type).
- AD-only parameters passed to Entra mode are ignored with warnings.
- Writes lifecycle inventory `Update` event with platform-aware metadata.

### Example

```powershell
Update-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User \
  -Description "Legacy SQL service account" -AddGroups "DnsAdmins"

Update-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal \
  -Description "Legacy BI Analytics Connector"
```

---

## `Disable-F4keH0undDecoy`

Disables AD or Entra decoy identity state.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Identity` | `String` | Yes | — | Target decoy identity. |
| `Platform` | `String` | No | `AD` | Target platform: `AD` or `Entra`. |
| `ObjectType` | `String` | No | `User` | AD: `User`, `Computer`; Entra: `ServicePrincipal`, `GuestUser`. |
| `DecoyType` | `String` | No | `LifecycleManagedDecoy` | Decoy classification label for lifecycle events. |
| `Server` | `String` | No | — | Domain Controller for AD operations (AD mode). |
| `Credential` | `PSCredential` | No | — | Credentials for AD operations (AD mode). |
| `PassThru` | `Switch` | No | `false` | Returns updated object. |

### Behavior Notes

- AD mode uses `Disable-ADAccount`.
- Entra mode uses `Update-MgServicePrincipal` / `Update-MgUser` with `AccountEnabled:$false`.
- If already disabled, records non-changing lifecycle state metadata.
- Writes lifecycle inventory `Disable` event.

### Example

```powershell
Disable-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User
Disable-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal
```

---

## `Enable-F4keH0undDecoy`

Enables AD or Entra decoy identity state.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Identity` | `String` | Yes | — | Target decoy identity. |
| `Platform` | `String` | No | `AD` | Target platform: `AD` or `Entra`. |
| `ObjectType` | `String` | No | `User` | AD: `User`, `Computer`; Entra: `ServicePrincipal`, `GuestUser`. |
| `DecoyType` | `String` | No | `LifecycleManagedDecoy` | Decoy classification label for lifecycle events. |
| `Server` | `String` | No | — | Domain Controller for AD operations (AD mode). |
| `Credential` | `PSCredential` | No | — | Credentials for AD operations (AD mode). |
| `PassThru` | `Switch` | No | `false` | Returns updated object. |

### Behavior Notes

- AD mode uses `Enable-ADAccount`.
- Entra mode uses `Update-MgServicePrincipal` / `Update-MgUser` with `AccountEnabled:$true`.
- If already enabled, records non-changing lifecycle state metadata.
- Writes lifecycle inventory `Enable` event.

### Example

```powershell
Enable-F4keH0undDecoy -Identity "svc_sql_legacy" -ObjectType User
Enable-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -ObjectType ServicePrincipal
```

---

## `Get-F4keH0undInventory`

Builds consolidated deceptive-element inventory from persistent lifecycle backend and/or report files.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Source` | `String` | No | `Auto` | Inventory source: `Auto`, `Events`, `Reports`. |
| `IncludeRemoved` | `Switch` | No | `false` | Events source: include decoys whose lifecycle state is removed. |
| `PreferSnapshot` | `Switch` | No | `false` | Events source: prefer snapshot file before event replay. |
| `ReportPath` | `String` | No | — | Reports source: read one specific deployment report CSV. |
| `ReportDirectory` | `String` | No | from config | Reports source: directory containing deployment reports. |
| `AllReports` | `Switch` | No | `false` | Reports source: include all report files, not just newest. |
| `SkipLiveStatus` | `Switch` | No | `false` | Skip AD live verification and return recorded lifecycle/report state. |
| `Server` | `String` | No | — | Domain Controller for live AD status checks. |
| `Credential` | `PSCredential` | No | — | Credentials for live AD status checks. |

### Behavior Notes

- `Auto` source resolution:
  1. Honors `InventorySettings.PreferredSource` when set to `Events` or `Reports`.
  2. Otherwise uses events if event log exists and has content.
  3. Falls back to reports.
- Returns normalized fields including `Identity`, `DecoyType`, `Platform`, `ObjectType`, `Status`, `LastAction`, `LastUpdated`, `Location`.

### Example

```powershell
Get-F4keH0undInventory -Source Events -IncludeRemoved -PreferSnapshot -SkipLiveStatus
```

---

## `Add-F4keH0undRelationship`

Adds a relationship between a decoy object and target object.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Decoy` | `PSObject` | Yes | — | Source decoy object to relate. |
| `Target` | `String` | Yes | — | Target object identity (e.g., group name). |
| `RelationshipType` | `String` | Yes | — | Allowed: `GroupMembership`. |
| `Environment` | `String` | Yes | — | `AD` or `Azure`. |
| `Server` | `String` | No | — | AD mode DC target. |
| `Credential` | `PSCredential` | No | — | AD mode credentials. |

### Behavior Notes

- AD + `GroupMembership`: executes `Add-ADGroupMember`.
- Azure mode currently warns (placeholder, not implemented relationship writes yet).

### Example

```powershell
$decoy = Get-ADUser "decoy_admin"
Add-F4keH0undRelationship -Decoy $decoy -Target "VPN Users" -RelationshipType GroupMembership -Environment AD -WhatIf
```

---

## `Remove-F4keH0undDecoy`

Removes/deletes AD or Entra decoys.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Identity` | `String` | Yes | — | Target decoy identity to remove. |
| `Platform` | `String` | No | `AD` | Target platform: `AD` or `Entra`. |
| `Server` | `String` | No | — | Domain Controller for AD operations (AD mode). |
| `Credential` | `PSCredential` | No | — | Credentials for AD operations (AD mode). |
| `DecoyType` | `String` | No | `User` | AD: `User`, `Computer`, `Group`; Entra: `ServicePrincipal`, `GuestUser`, `AppRegistration`. Alias: `ObjectType`. |

### Behavior Notes

- AD mode removes group memberships first when present.
- AD mode deletes objects via `Remove-ADUser` / `Remove-ADComputer` / `Remove-ADGroup`.
- Entra mode deletes objects via `Remove-MgServicePrincipal` / `Remove-MgUser` / `Remove-MgApplication`.
- Writes lifecycle inventory `Remove` event.

### Example

```powershell
Remove-F4keH0undDecoy -Identity "svc_sql_legacy" -DecoyType User -WhatIf
Remove-F4keH0undDecoy -Identity "legacy-bi-app" -Platform Entra -DecoyType ServicePrincipal -WhatIf
```

---

## `Get-F4keH0undConfig`

Loads effective runtime configuration from `config.json` (with fallback defaults).

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ConfigPath` | `String` | No | module `config.json` | Optional path to alternate config file. |
| `Section` | `String` | No | full config | Returns only one section when specified. Allowed values: `RecyclingPreferences`, `SafetyFilters`, `DeploymentSettings`, `RankingWeights`, `AuditSettings`, `AdvancedOptions`, `InventorySettings`. |

### Output

Returns full config object or selected section object.

### Example

```powershell
Get-F4keH0undConfig -Section InventorySettings
```

---

## `Test-F4keH0undCoverage`

Computes AD/Entra lifecycle coverage and parity status from current inventory.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Source` | `String` | No | `Auto` | Inventory source: `Auto`, `Events`, `Reports`. |
| `IncludeRemoved` | `Switch` | No | `false` | Includes removed entries in inventory-based calculations. |
| `PreferSnapshot` | `Switch` | No | `false` | Events source: prefer snapshot before replay. |
| `SkipLiveStatus` | `Switch` | No | `false` | Skip AD live verification during inventory read. |
| `Server` | `String` | No | — | Domain Controller for AD live status checks. |
| `Credential` | `PSCredential` | No | — | Credentials for AD live status checks. |
| `TargetParityRatio` | `Double` | No | `1.0` | Required Entra-to-AD ratio for each mapped family. |
| `BloodHoundPath` | `String` | No | — | Optional AD opportunity context path. |
| `AzureHoundPath` | `String` | No | — | Optional Entra opportunity context path. |

### Output

Returns a summary object containing:

- `IsParityMet`
- `ADLifecycleCoveragePercent`
- `EntraLifecycleCoveragePercent`
- `EntraToADActiveRatio`
- `FamilyStatus` (family gaps and targets)
- `Matrix` (decoy-type capability + deployment counts)

### Example

```powershell
Test-F4keH0undCoverage -Source Events -PreferSnapshot -SkipLiveStatus
Test-F4keH0undCoverage -AzureHoundPath ./AzureHound_Data -TargetParityRatio 1.0
```

---

## `Test-F4keH0undConfig`

Validates configuration structure and key values.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ConfigPath` | `String` | No | module `config.json` | Optional path to alternate config file. |

### Output

Returns object with:

- `IsValid` (`Boolean`)
- `Warnings` (`String[]`)
- `Errors` (`String[]`)

### Example

```powershell
$validation = Test-F4keH0undConfig
$validation | Format-List
```

---

## Utility Script (Repository-Level)

### `Reinstall-F4keH0und.ps1`

Not a module cmdlet, but an operational script used to clean stale module installs and reinstall from local source.

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `SourcePath` | `String` | No | script root | Local repo path used for reinstall copy. |
| `PullLatest` | `Switch` | No | `false` | Performs `git fetch --all` + hard reset to origin branch before reinstall. |
| `Branch` | `String` | No | `main` | Branch used with `-PullLatest`. |

Example:

```powershell
./Reinstall-F4keH0und.ps1 -PullLatest
```

---

## Quick Discovery Commands

```powershell
Get-Command -Module F4keH0und
Get-Help Find-F4keH0undOpportunity -Full
Get-Help Update-F4keH0undDecoy -Examples
```
