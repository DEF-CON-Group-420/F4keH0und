# Command Reference

This document describes every exported `F4keH0und` module command, its parameters, expected behavior, and practical usage patterns.

Coverage of command sections in this file is enforced in CI by `scripts/Test-CommandReferenceCoverage.ps1`.

## Command Inventory

Current exported commands:

1. `Find-F4keH0undOpportunity`
2. `New-F4keH0undDecoy`
3. `Get-F4keH0undElementType`
4. `New-F4keH0undElement`
5. `New-F4keH0undToken`
6. `Register-F4keH0undTokenTrigger`
7. `Update-F4keH0undElement`
8. `Disable-F4keH0undElement`
9. `Enable-F4keH0undElement`
10. `Remove-F4keH0undElement`
11. `Sync-F4keH0undEntraParity`
12. `Update-F4keH0undDecoy`
13. `Disable-F4keH0undDecoy`
14. `Enable-F4keH0undDecoy`
15. `Get-F4keH0undInventory`
16. `Add-F4keH0undRelationship`
17. `Remove-F4keH0undDecoy`
18. `Get-F4keH0undConfig`
19. `Test-F4keH0undCoverage`
20. `Test-F4keH0undConfig`

---

## Common PowerShell Behavior

- All exported commands support standard common parameters (`-Verbose`, `-Debug`, `-ErrorAction`, etc.).
- The following commands support `-WhatIf`/`-Confirm` (safe simulation via `ShouldProcess`):
  - `New-F4keH0undDecoy`
  - `New-F4keH0undElement`
  - `New-F4keH0undToken`
  - `Register-F4keH0undTokenTrigger`
  - `Update-F4keH0undElement`
  - `Disable-F4keH0undElement`
  - `Enable-F4keH0undElement`
  - `Remove-F4keH0undElement`
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
| `WindowsComputerName` | `String[]` | No | — | AD mode: explicit Windows host list for artifact opportunity ranking. |
| `MaxWindowsElementOpportunities` | `Int32` | No | `8` | AD mode: cap on returned Windows artifact opportunities. |
| `EntraIncludeServicePrincipals` | `Switch` | No | auto-all | Include disabled service principals in Entra scan. |
| `EntraIncludeGuestUsers` | `Switch` | No | auto-all | Include inactive guest users in Entra scan. |
| `EntraIncludeAppRegistrations` | `Switch` | No | auto-all | Include unused app registrations in Entra scan. |
| `EntraRecyclingMinimumAgeDays` | `Int32` | No | `180` | Minimum age for recyclable Entra objects. |
| `EntraRecyclingMaximumAgeDays` | `Int32` | No | `3650` | Maximum age for recyclable Entra objects. |
| `EntraPreferRecycling` | `Switch` | No | `false` | Boosts Entra recycling opportunity rank. |
| `EntraRecyclingOnly` | `Switch` | No | `false` | Returns only Entra recycling opportunities. |

### Output

Returns a collection of opportunity objects with fields such as `ID`, `Rank`, `DecoyType`, `Strategy`, `Justification`, and `Template`.

When `-WindowsComputerName` is supplied, additional Windows artifact opportunities are included with `Strategy = Artifact` and template hints for `New-F4keH0undElement`.

In Entra mode, template payloads now include themed lure metadata (for example `LureTheme`, `RoleAssignmentHint`, `ConsentScopeBait`, `ConditionalAccessBypassHint`, `SecretHint`) used by downstream deployment and inventory tracking.

### Example

```powershell
Find-F4keH0undOpportunity -BloodHoundPath ./BH_Data -PreferRecycling -Verbose
Find-F4keH0undOpportunity -BloodHoundPath ./BH_Data -WindowsComputerName WIN-APP-01,WIN-APP-02 -MaxWindowsElementOpportunities 6
Find-F4keH0undOpportunity -AzureHoundPath ./AzureHound_Data -EntraPreferRecycling -Verbose
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
- For Entra decoys, forwards template lure metadata (theme, role/consent/conditional-access hints, persona fields) to deployment helpers and inventory events.
- Generates deployment report data and optional CSV handover.
- Writes lifecycle inventory `Deploy` events to persistent backend with platform-aware identity/location fields.

### Example

```powershell
New-F4keH0undDecoy -BloodHoundPath ./BH_Data -Execute -PreferRecycling -WhatIf
```

---

## `Get-F4keH0undElementType`

Lists supported Windows-only artifact element families/types from the element registry.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Family` | `String` | No | — | Optional family filter (`ServiceLure`, `RpcBait`, `ApiHookBait`, `RuntimeArtifact`, `IdentityTokenBait`, `CloudTokenBait`, `CredentialBait`). |
| `Platform` | `String` | No | `Windows` | Platform filter (Phase 3 supports `Windows` only). |
| `Detailed` | `Switch` | No | `false` | Returns full registry metadata fields. |

### Example

```powershell
Get-F4keH0undElementType
Get-F4keH0undElementType -Family ApiHookBait -Detailed
```

---

## `New-F4keH0undElement`

Deploys Windows artifact deception elements to target hosts over WinRM/PSRP.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ElementType` | `String` | Yes | — | Element type (`ServiceDefinitionDecoy`, `RpcEndpointDecoy`, `ApiHookConfigDecoy`, `ProcessThreadArtifactDecoy`, `IdentityBreadcrumbTokenDecoy`, `CloudApiCanaryTokenDecoy`, `CredentialFileTokenDecoy`). |
| `ComputerName` | `String[]` | Yes | — | Windows hosts to deploy to. |
| `Name` | `String` | No | generated | Logical element name used for artifact rendering. |
| `TemplateData` | `IDictionary` | No | `{}` | Template fields for artifact content rendering. |
| `ArtifactRoot` | `String` | No | from config | Remote root folder for element artifacts. |
| `Tag` | `String[]` | No | — | Metadata tags stored in inventory events. |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port (e.g., 5985/5986). |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `ThrottleLimit` | `Int32` | No | from config | Reserved for future parallelized execution workflows. |
| `AuditLogPath` | `String` | No | — | Optional audit metadata field. |
| `PassThru` | `Switch` | No | `false` | Returns deployed element records. |

### Behavior Notes

- Windows-only artifact deployment model (no AD/Entra object creation).
- Uses WinRM/PSRP channel and writes inventory `Deploy` events with `Platform=Windows`.
- Default deployment mode is artifact-only (no active listener binaries).

### Example

```powershell
New-F4keH0undElement -ElementType ApiHookConfigDecoy -ComputerName WIN-APP-01 -WhatIf
```

---

## `New-F4keH0undToken`

Deploys identity/token-prioritized Windows bait artifacts using low-cost profiles.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `TokenType` | `String` | No | `IdentityBreadcrumb` | Token profile: `IdentityBreadcrumb`, `CloudApiCanary`, `CredentialFile`. |
| `ComputerName` | `String[]` | Yes | — | Windows target hosts. |
| `Name` | `String` | No | generated | Logical package name for rendered artifacts. |
| `TemplateData` | `IDictionary` | No | `{}` | Optional token payload template fields. |
| `Tag` | `String[]` | No | defaults + custom | Additional metadata tags merged with token defaults. |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port override. |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `PassThru` | `Switch` | No | `false` | Returns deployed element records. |

### Behavior Notes

- Maps token profiles to Windows element types:
  - `IdentityBreadcrumb` → `IdentityBreadcrumbTokenDecoy`
  - `CloudApiCanary` → `CloudApiCanaryTokenDecoy`
  - `CredentialFile` → `CredentialFileTokenDecoy`
- Auto-generates a canary token value when none is supplied.
- Uses `New-F4keH0undElement` under the hood and preserves lifecycle coverage.

### Example

```powershell
New-F4keH0undToken -TokenType IdentityBreadcrumb -ComputerName WIN-APP-01 -WhatIf
New-F4keH0undToken -TokenType CloudApiCanary -ComputerName WIN-API-01,WIN-API-02 -Credential (Get-Credential) -PassThru
```

---

## `Register-F4keH0undTokenTrigger`

Records token/identity trigger telemetry in persistent inventory and updates correlation/alert fields.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `Identity` | `String[]` | No | — | Inventory identity to correlate (element ID or decoy identity). Optional when connector payload contains mapped identity fields. |
| `ConnectorPreset` | `String` | No | — | Telemetry connector preset ID (`SysmonEvent11FileCreate`, `SysmonEvent3NetworkConnect`, `WindowsSecurity4624Logon`, `WindowsSecurity4663ObjectAccess`, `WindowsSecurity4688ProcessCreate`). Must be paired with `TelemetryPayload`. |
| `TelemetryPayload` | `Object` | No | — | Raw SIEM/SOAR telemetry object (hashtable/PSObject) used by `ConnectorPreset` mapping. |
| `DecoyType` | `String` | No | from inventory | Optional decoy/element type override. |
| `Platform` | `String` | No | from inventory/`Windows` | Optional platform override (`AD`, `Entra`, `Windows`). |
| `ObjectType` | `String` | No | from inventory/`Element` | Optional object type override. |
| `TriggerType` | `String` | No | `TokenUse` | Trigger classification (`TokenUse`, `CredentialUse`, `ApiAuth`, `FileAccess`, `ProcessAccess`, `NetworkAccess`, `ManualInvestigation`, `Other`). |
| `TriggerSource` | `String` | No | — | Telemetry source hint (for example `Sysmon:EventID11`). |
| `Actor` | `String` | No | — | Actor identity associated with trigger. |
| `ComputerName` | `String` | No | — | Host where trigger was observed. |
| `EvidenceRef` | `String` | No | — | Evidence reference (event ID/case/artifact path). |
| `TokenIdentifier` | `String` | No | — | Token fingerprint identifier (`sha256:<short>` recommended). |
| `TokenValue` | `String` | No | — | Raw token value; hashed to fingerprint before storage. |
| `SignalCount` | `Int32` | No | `1` | Number of correlated telemetry signals in this trigger event. |
| `Confidence` | `Double` | No | `80` | Trigger confidence score (0-100). |
| `Correlated` | `Switch` | No | `false` | Upstream hint that token correlation is already verified. |
| `PassThru` | `Switch` | No | `false` | Returns updated inventory row for identity. |

### Behavior Notes

- Connector mode requires both `ConnectorPreset` and `TelemetryPayload`.
- Connector presets are loaded from `TelemetrySettings.ConnectorPackPath` (`./telemetry-connectors.windows.json` by default), with built-in fallback presets.
- Writes inventory event with `Action = Trigger`.
- Correlates `TokenIdentifier` against known token fingerprints when available.
- Updates inventory trigger fields (`TriggerCount`, `LastTriggeredAt`, `TokenCorrelationStatus`).
- Updates alert model output (`AlertScore`, `AlertSeverity`, `AlertReasons`).
- Writes connector metadata (`ConnectorPreset`) into trigger event metadata when connector mode is used.

### Example

```powershell
Register-F4keH0undTokenTrigger -Identity fhlg-win-cloudapicanarytokendecoy-a1b2c3d4e5f6 -TriggerType ApiAuth -TriggerSource 'Sysmon:EventID3' -SignalCount 3 -Confidence 90
Register-F4keH0undTokenTrigger -Identity svc_legacy_sync -Platform AD -ObjectType User -TriggerType CredentialUse -TokenValue 'decoy-passphrase' -PassThru
Register-F4keH0undTokenTrigger -ConnectorPreset SysmonEvent11FileCreate -TelemetryPayload @{ Identity = 'fhlg-win-identitybreadcrumbtokendecoy-a1b2c3d4e5f6'; User = 'CORP\j.smith'; Computer = 'WIN-APP-01'; EventRecordId = '42755'; TargetFilename = 'C:\ProgramData\F4keH0und-LG\Elements\identity\notes.txt' } -PassThru
```

---

## `Update-F4keH0undElement`

Updates previously deployed Windows artifact elements by `ElementId`.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ElementId` | `String[]` | Yes | — | Existing element IDs to update. |
| `TemplateData` | `IDictionary` | No | merged | Template overrides merged with existing metadata template data. |
| `Name` | `String` | No | existing | Optional replacement element name. |
| `Tag` | `String[]` | No | existing | Optional replacement tags. |
| `ComputerName` | `String[]` | No | from inventory | Optional host override(s). |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port override. |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `ThrottleLimit` | `Int32` | No | from config | Reserved for future parallelized execution workflows. |
| `PassThru` | `Switch` | No | `false` | Returns updated element records. |

### Behavior Notes

- Resolves host/metadata from inventory state when not explicitly provided.
- Re-renders artifacts and writes inventory `Update` events.

### Example

```powershell
Update-F4keH0undElement -ElementId fhlg-win-apihookconfigdecoy-1234567890ab -TemplateData @{ ApiBaseUrl = 'https://legacy-api2.internal.corp' }
```

---

## `Disable-F4keH0undElement`

Disables deployed Windows artifact elements (soft lifecycle state transition).

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ElementId` | `String[]` | Yes | — | Existing element IDs to disable. |
| `Reason` | `String` | No | — | Optional disable reason stored in metadata. |
| `ComputerName` | `String[]` | No | from inventory | Optional host override(s). |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port override. |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `PassThru` | `Switch` | No | `false` | Returns updated element records. |

### Example

```powershell
Disable-F4keH0undElement -ElementId fhlg-win-rpcendpointdecoy-abcdef123456 -Reason 'Maintenance window'
```

---

## `Enable-F4keH0undElement`

Re-enables deployed Windows artifact elements to armed state.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ElementId` | `String[]` | Yes | — | Existing element IDs to enable. |
| `ComputerName` | `String[]` | No | from inventory | Optional host override(s). |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port override. |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `PassThru` | `Switch` | No | `false` | Returns updated element records. |

### Example

```powershell
Enable-F4keH0undElement -ElementId fhlg-win-rpcendpointdecoy-abcdef123456
```

---

## `Remove-F4keH0undElement`

Removes deployed Windows artifact elements from target hosts.

### Parameters

| Parameter | Type | Required | Default | Meaning |
|---|---|---:|---|---|
| `ElementId` | `String[]` | Yes | — | Existing element IDs to remove. |
| `ComputerName` | `String[]` | No | from inventory | Optional host override(s). |
| `PurgeTelemetryMap` | `Switch` | No | `false` | Records intent to purge telemetry mapping metadata. |
| `Credential` | `PSCredential` | No | — | WinRM credential. |
| `Port` | `Int32` | No | from config | WinRM port override. |
| `UseSSL` | `Switch` | No | from config | Uses WinRM over HTTPS. |
| `Authentication` | `String` | No | from config | WinRM authentication method. |
| `PassThru` | `Switch` | No | `false` | Returns removal records. |

### Example

```powershell
Remove-F4keH0undElement -ElementId fhlg-win-servicedefinitiondecoy-1234abcd5678 -WhatIf
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
- Carries Entra lure metadata (`LureTheme`, `RoleAssignmentHint`, `ConsentScopeBait`, `ConditionalAccessBypassHint`, `SecretHint`) into deployment and event metadata.
- Returns before/after coverage state, planned opportunities (including `LureTheme` and consent/CA hints), and deployment outcomes.

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
| `Platform` | `String` | No | — | Post-load platform filter: `AD`, `Entra`, or `Windows`. |
| `ElementType` | `String[]` | No | — | Post-load filter by `DecoyType` values. |
| `ElementFamily` | `String[]` | No | — | Post-load filter by metadata family (for example `ServiceLure`, `ApiHookBait`). |
| `ComputerName` | `String[]` | No | — | Post-load filter by metadata host (`ComputerName` or `TargetHost`). |
| `Status` | `String[]` | No | — | Post-load filter by lifecycle or recorded status value. |
| `AlertSeverity` | `String[]` | No | — | Post-load filter by alert severity (`None`, `Low`, `Medium`, `High`, `Critical`). |
| `MinAlertScore` | `Int32` | No | — | Post-load minimum alert score filter (0-100). |

### Behavior Notes

- `Auto` source resolution:
  1. Honors `InventorySettings.PreferredSource` when set to `Events` or `Reports`.
  2. Otherwise uses events if event log exists and has content.
  3. Falls back to reports.
- Returns normalized fields including `Identity`, `DecoyType`, `Platform`, `ObjectType`, `Status`, `LastAction`, `LastUpdated`, `Location`.
- Events-backed rows include trigger/correlation fields (`TriggerCount`, `LastTriggeredAt`, `TokenCorrelationStatus`) and alert model outputs (`AlertScore`, `AlertSeverity`, `AlertReasons`).
- Platform/element/host/status filters are applied after source normalization.
- Alert filters (`AlertSeverity`, `MinAlertScore`) are applied after source normalization.

### Example

```powershell
Get-F4keH0undInventory -Source Events -IncludeRemoved -PreferSnapshot -SkipLiveStatus
Get-F4keH0undInventory -Source Events -Platform Windows -ElementFamily ApiHookBait -Status Armed
Get-F4keH0undInventory -Source Events -Platform Windows -AlertSeverity High,Critical -MinAlertScore 65
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
| `Section` | `String` | No | full config | Returns only one section when specified. Allowed values: `RecyclingPreferences`, `SafetyFilters`, `DeploymentSettings`, `RankingWeights`, `AuditSettings`, `AdvancedOptions`, `InventorySettings`, `WindowsDeploymentSettings`, `TelemetrySettings`, `ElementRegistrySettings`. |

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
