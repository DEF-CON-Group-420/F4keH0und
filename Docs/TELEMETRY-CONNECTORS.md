# Telemetry Connector Pack

This document describes the preset-based telemetry connector model used by `Register-F4keH0undTokenTrigger` for SIEM/SOAR integrations.

---

## Purpose

The connector pack standardizes raw telemetry payloads (Sysmon + Windows Security) into F4keH0und trigger fields without requiring custom per-source parsing in every workflow.

Command entry point:

```powershell
Register-F4keH0undTokenTrigger -ConnectorPreset <PresetId> -TelemetryPayload <Object>
```

---

## Pack Location and Resolution

- Default connector pack file: `telemetry-connectors.windows.json` (repository root).
- Config key: `TelemetrySettings.ConnectorPackPath` in `config.json`.
- If the configured file is missing or invalid, built-in preset defaults are used automatically.

---

## Current Presets

| Preset ID | Source | TriggerType | TriggerSource | Default SignalCount | Default Confidence |
|---|---|---|---|---:|---:|
| `SysmonEvent11FileCreate` | Sysmon Event ID 11 | `FileAccess` | `Sysmon:EventID11` | 2 | 86 |
| `CanaryTextPackSysmonFileCreate` | Sysmon Event ID 11 (text-pack tuned) | `FileAccess` | `Sysmon:EventID11` | 2 | 89 |
| `CanaryTextPackSecurityObjectAccess` | Security Event ID 4663 (text-pack tuned) | `FileAccess` | `WindowsSecurity:EventID4663` | 2 | 87 |
| `SysmonEvent3NetworkConnect` | Sysmon Event ID 3 | `ApiAuth` | `Sysmon:EventID3` | 3 | 90 |
| `WindowsSecurity4624Logon` | Security Event ID 4624 | `CredentialUse` | `WindowsSecurity:EventID4624` | 2 | 84 |
| `WindowsSecurity4663ObjectAccess` | Security Event ID 4663 | `FileAccess` | `WindowsSecurity:EventID4663` | 2 | 82 |
| `WindowsSecurity4688ProcessCreate` | Security Event ID 4688 | `ProcessAccess` | `WindowsSecurity:EventID4688` | 1 | 74 |

---

## Payload Mapping Contract

Each preset defines `FieldMap` entries to resolve values from incoming payload objects.

Target trigger fields:

- `Identity` (required unless explicitly passed via command parameter)
- `Actor`
- `ComputerName`
- `EvidenceRef`
- `TokenIdentifier`

Resolution rules:

1. Paths are evaluated in declared order; first non-empty value wins.
2. Dot notation is supported for nested objects (for example `Event.System.Computer`).
3. `SignalCount` and `Confidence` can be overridden by payload keys of the same name.
4. Command-line parameters always take precedence over mapped values.
5. If no `Identity` is mapped, trigger ingestion can resolve identity from inventory artifact path hints (`ArtifactLocations` / `TokenPathHints`).

Token handling:

- `TokenIdentifier` values are normalized to fingerprint form (`sha256:<short>`).
- Raw values are hashed before storage.

---

## Example: Connector-Driven Trigger Registration

```powershell
$event = @{
    Identity            = "fhlg-win-cloudapicanarytokendecoy-a1b2c3d4e5f6"
    User                = "CORP\\j.smith"
    Computer            = "WIN-API-01"
    EventRecordId       = "sysmon-92117"
    DestinationHostname = "graph.microsoft.com"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset SysmonEvent3NetworkConnect `
    -TelemetryPayload $event `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, AlertScore, AlertSeverity

$textPackEvent = @{
    TargetFilename = "C:\ProgramData\F4keH0und-LG\Elements\fhlg-win-canarytexttokenpackdecoy-a1b2c3d4e5f6\docs\IdentityRepo-CanaryPack-operator-runbook.decoy.md"
    User           = "CORP\\j.smith"
    Computer       = "WIN-DEV-01"
    EventRecordId  = "sysmon-22007"
}

Register-F4keH0undTokenTrigger `
    -ConnectorPreset CanaryTextPackSysmonFileCreate `
    -TelemetryPayload $textPackEvent `
    -PassThru |
    Format-List Identity, LastTriggerType, LastTriggerSource, TokenCorrelationStatus, AlertSeverity
```

---

## Customization Guidance

To add your own source mapping:

1. Copy `telemetry-connectors.windows.json`.
2. Add or modify `Presets` entries and `FieldMap` paths.
3. Point `TelemetrySettings.ConnectorPackPath` to the custom file.
4. Run `Test-F4keH0undConfig` to verify file resolution warnings.

Keep preset IDs stable for automation and playbook compatibility.
