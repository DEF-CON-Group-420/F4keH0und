# F4keH0und - Last Generation — Detailed Roadmap

This roadmap defines the next evolution of the project with a PowerShell-first, cross-platform approach and identity/token-prioritized deception coverage.

---

## 1) Program Goals

- Keep **PowerShell (`pwsh`)** as the primary operator interface.
- Support **Windows, macOS, Linux** when required modules are installed.
- Deliver a unified **deceptive element interface** (inventory + status + location + lifecycle).
- Expand **Entra parity** to match AD depth.
- Add new deception element families beyond accounts/groups.
- Provide full lifecycle commands (create, inspect, update, redesign, disable, remove, recycle).
- Prioritize **low-cost/high-detection** deception assets.

---

## 2) Scope Mapped to Your Requirements

1. **PowerShell-first cross-platform**
   - Standardize on PowerShell 7+.
   - Remove OS-specific install assumptions.
   - Validate paths and module behavior on all 3 platforms.

2. **Unified interface for deceptive elements**
   - Add inventory model covering AD, Entra, tokens, services, hooks, and protocol baits.
   - Show where deployed, current status, and last verification timestamp.

3. **Entra coverage widened to AD parity**
   - Extend Entra identity, app, role, and relationship decoys.
   - Add Entra lifecycle operations (deploy/update/remove/recycle).

4. **Additional element types**
   - Add fake threads/process-like lures, service lures, RPC server/client artifacts, and API hook bait.

5. **Full lifecycle command surface**
   - Build create/read/update/redesign/disable/remove/recycle workflows.

6. **Identity and token priority**
   - Implement first-class identity decoys, credential bait, and token telemetry.

7. **Low-cost / high-efficiency features**
   - Prioritize text/config/metadata bait over expensive interactive honeypots.

---

## 3) Target Command Surface (Last Generation)

- `Find-F4keH0undOpportunity` (existing, expanded)
- `New-F4keH0undDecoy` (existing, expanded)
- `Get-F4keH0undInventory` (implemented: reports + persistent events)
- `Update-F4keH0undDecoy` (implemented)
- `Redesign-F4keH0undDecoy` (new)
- `Disable-F4keH0undDecoy` (implemented)
- `Enable-F4keH0undDecoy` (implemented)
- `Remove-F4keH0undDecoy` (existing, expanded)
- `New-F4keH0undToken` (new)
- `Test-F4keH0undCoverage` (new)
- `Sync-F4keH0undEntraParity` (new)

---

## 4) Detailed Phased Plan

## Phase 0 — Foundation (Week 1)

- Finalize rebrand to **F4keH0und - Last Generation** across docs and metadata.
- Ensure install/reinstall flows are OS-aware.
- Add baseline inventory interface and report ingestion.
- Define a normalized schema for deceptive elements.

**Deliverables**
- Updated README + badges + positioning
- Cross-platform reinstall behavior
- Inventory command returning status model

## Phase 1 — Inventory & Lifecycle Core (Weeks 2–3)

- Create persistent inventory store (JSONL/SQLite selectable backend).
- Track lifecycle events (`Deployed`, `Updated`, `Disabled`, `Removed`, `Recycled`).
- Add CRUD-style lifecycle cmdlets for AD objects.
- Add versioning for each decoy profile.

**Deliverables**
- `Update-F4keH0undDecoy`
- `Disable-F4keH0undDecoy` / `Enable-F4keH0undDecoy`
- Event-sourced inventory history

**Current implementation status:**
- ✅ Event-sourced NDJSON inventory backend and snapshot cache
- ✅ `Update-F4keH0undDecoy`
- ✅ `Disable-F4keH0undDecoy` / `Enable-F4keH0undDecoy`
- ✅ Lifecycle event writes from deploy/update/disable/enable/remove flows

## Phase 2 — Entra Parity Expansion (Weeks 4–5)

- Extend Entra opportunities to include:
  - role-assignment lures
  - stale app secrets/certs lure profiles
  - conditional access bypass bait patterns
  - OAuth consent trap elements
- Add Entra lifecycle commands matching AD operations.
- Add parity score output (`AD vs Entra` coverage matrix).

**Deliverables**
- `Test-F4keH0undCoverage`
- `Sync-F4keH0undEntraParity`
- Entra lifecycle remove/update support

**Current implementation status:**
- ✅ Entra deployment switch support in `New-F4keH0undDecoy` for service principal, guest user, and app registration decoys
- ✅ Entra lifecycle parity in `Update/Disable/Enable/Remove-F4keH0undDecoy`
- ✅ Entra lifecycle events written to persistent inventory with canonical identity/location mapping
- ✅ Parity scoring command surface (`Test-F4keH0undCoverage`, `Sync-F4keH0undEntraParity`)
- ✅ Broadened Entra lure templates with role-assignment, OAuth consent, conditional-access bypass, and stale-credential themed metadata
- ✅ Expanded OAuth app metadata bait fields in Entra templates and lifecycle metadata (`OAuthPermissionBait`, `OAuthGrantTypeBait`, `OAuthResourceBait`, `OAuthRedirectUriBait`, `OAuthAdminConsentHint`)

## Phase 3 — New Element Families (Weeks 6–7)

- Add low-resource element plugins:
  - fake service definitions
  - fake RPC endpoint metadata/artifacts
  - API hook bait configs
  - fake thread/process-name artifacts (metadata-driven)
- Integrate into opportunity ranking.

**Deliverables**
- Plugin-based element type registry
- New decoy type templates for each family

**Current implementation status:**
- ✅ Windows element-type registry (`element-types.windows.json`) with service, RPC, API-hook, and runtime artifact families
- ✅ Lifecycle command surface (`Get/New/Update/Disable/Enable/Remove-F4keH0undElement`)
- ✅ WinRM/PSRP execution path with artifact-only remote deployment model
- ✅ Inventory integration for Windows platform entries and post-load filters (`Platform`, `ElementType`, `ElementFamily`, `ComputerName`, `Status`)
- ✅ Config model expansion (`WindowsDeploymentSettings`, `TelemetrySettings`, `ElementRegistrySettings`)
- ✅ Opportunity-ranking integration for Windows element-family recommendations via `Find-F4keH0undOpportunity -WindowsComputerName`

## Phase 4 — Token & Identity Priority (Weeks 8–9)

- Build identity/token deception pack:
  - fake credential files and token strings
  - honey API keys in controlled canary channels
  - decoy SPNs and delegated identity paths
- Add telemetry connectors for trigger collection.

**Deliverables**
- `New-F4keH0undToken`
- Token trigger correlation in inventory status
- High-confidence alert scoring for identity/token interactions

**Current implementation status:**
- ✅ Token-priority command surface (`New-F4keH0undToken`)
- ✅ New token-focused Windows element families (`IdentityTokenBait`, `CloudTokenBait`, `CredentialBait`)
- ✅ Token/identity artifact templates added to Windows deployment plane
- ✅ Ranking priority boost for identity/token/credential families in Windows artifact opportunities
- ✅ Token-trigger correlation fields in persistent inventory (`TriggerCount`, `LastTriggeredAt`, `TokenCorrelationStatus`)
- ✅ Alert-scoring model outputs in inventory (`AlertScore`, `AlertSeverity`, `AlertReasons`)
- ✅ Telemetry connector pack for direct SIEM/SOAR ingestion templates (`telemetry-connectors.windows.json` + preset mapping in `Register-F4keH0undTokenTrigger`)

## Phase 5 — Hardening & Operations (Week 10)

- Add rollout profiles (`Lab`, `Pilot`, `Production`).
- Add drift detection and automatic stale-decoy redesign suggestions.
- Complete operational runbooks and response playbooks.

**Deliverables**
- Production readiness checklist
- CI validation and doc/test refresh

**Current implementation status:**
- ✅ Rollout profiles (`Lab`, `Pilot`, `Production`) implemented in config + command integration (`New-F4keH0undElement`, `New-F4keH0undToken`, `New-F4keH0undDecoy`, `Sync-F4keH0undEntraParity`)
- ✅ Drift detection + redesign suggestions implemented (`Test-F4keH0undDrift`)
- ✅ Response playbook templates implemented (`Docs/RESPONSE-PLAYBOOKS.md` + `scripts/New-TokenTriggerResponsePlaybook.ps1`)
- ✅ Low-cost identity-attribute lure expansion implemented (display-name/department/title/company/office/location + owner/group hints in AD/Entra/Windows templates)
- ✅ Canary text-token packs implemented for scripts/config/docs with lightweight connector hooks (`CanaryTextTokenPackDecoy`, `CanaryTextPackSysmonFileCreate`, `CanaryTextPackSecurityObjectAccess`)
- ✅ Service credential packs implemented for vault-like paths with lightweight connector hooks (`ServiceCredentialPackDecoy`, `ServiceCredentialPackSysmonFileCreate`, `ServiceCredentialPackSecurityObjectAccess`)
- ✅ Honey SPN + constrained role lure combinations implemented for AD Kerberoast workflows (`KerberoastableUser` with `GroupsToAdd` / `ConstrainedRoleLure` metadata)
- ✅ Fake admin troubleshooting artifact packs implemented with lightweight connector hooks (`AdminTroubleshootingTokenPackDecoy`, `AdminTroubleshootingPackSysmonFileCreate`, `AdminTroubleshootingPackSecurityObjectAccess`)
- ✅ RPC/API endpoint-name bait records implemented with lifecycle hooks and lightweight connector presets (`RpcEndpointBait*`, `ApiEndpointBait*`)
- ✅ Endpoint-name preset alert scoring tuned with correlation/source weighting for `RpcEndpointBait*` and `ApiEndpointBait*`
- ✅ CI command-reference coverage guard in place (`scripts/Test-CommandReferenceCoverage.ps1`)

---

## 5) Low-Cost / High-Efficiency Feature Backlog (Prioritized)

1. ✅ **Decoy identity attributes** (display names, descriptions, group hints)
2. ✅ **Canary text tokens** in scripts/config/docs repositories
3. ✅ **Fake service credentials** in vault-like paths with monitoring
4. ✅ **Decoy OAuth app metadata** (unused but attractive permissions)
5. ✅ **Honey SPN + constrained role lure combinations**
6. ✅ **Fake admin troubleshooting artifacts** (`.txt`, `.ps1`, `.xml`) with token bait
7. ✅ **RPC/API endpoint-name bait records** without running full emulators

These deliver high attacker interaction probability with low compute and maintenance cost.

---

## 6) Immediate Next Steps (Suggested Execution Order)

1. Tune SIEM/SOAR mappings and response playbooks for the new endpoint/troubleshooting connector presets.
