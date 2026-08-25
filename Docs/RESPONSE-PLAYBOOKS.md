# Token Trigger Response Playbooks

This document provides operational response templates for **High** and **Critical** token-trigger alerts in F4keH0und - Last Generation.

Use it as the SOC handover standard for incidents raised from:

- `Register-F4keH0undTokenTrigger`
- `Get-F4keH0undInventory` (`AlertSeverity`, `AlertScore`)
- `Test-F4keH0undDrift` (redesign/rotation recommendations)

---

## 1) Scope and Activation

Activate this playbook when inventory indicates:

- `AlertSeverity = High` with `AlertScore >= 65`, or
- `AlertSeverity = Critical` with `AlertScore >= 85`.

Recommended source query:

```powershell
Get-F4keH0undInventory -Source Events -AlertSeverity High,Critical -MinAlertScore 65 -SkipLiveStatus |
    Sort-Object AlertScore -Descending
```

---

## 2) Severity Profiles

### High Severity Template

**Response targets**

- Acknowledge in 15 minutes
- Assign analyst in 30 minutes
- Containment decision in 60 minutes
- Platform-owner escalation in 90 minutes

**Immediate actions (0-60 min)**

1. Validate trigger authenticity (`LastTriggerSource`, `LastTriggerEvidence`, `LastTriggerActor`).
2. Determine scope: single identity/host vs. lateral spread indicators.
3. Preserve evidence and SIEM timeline artifacts.
4. Contain if needed by temporarily disabling exposed decoy element.
5. Notify on-call detection engineer.

**Containment command patterns**

```powershell
# Windows artifact decoy containment
Disable-F4keH0undElement -ElementId <ElementId> -Reason "High token-trigger triage" -WhatIf

# Later restoration after triage
Enable-F4keH0undElement -ElementId <ElementId> -WhatIf
```

---

### Critical Severity Template

**Response targets**

- Acknowledge in 5 minutes
- Incident commander assigned in 10 minutes
- Containment initiated in 15 minutes
- Identity/platform-owner escalation immediately

**Immediate actions (0-30 min)**

1. Validate trigger and confirm no known benign/maintenance activity.
2. Isolate affected endpoint/session when compromise is likely.
3. Disable exposed decoy element where active interaction continues.
4. Capture volatile host context (process, network, logon session).
5. Start incident bridge and communications cadence.

**Containment command patterns**

```powershell
# Windows artifact decoy emergency containment
Disable-F4keH0undElement -ElementId <ElementId> -Reason "Critical token-trigger containment" -WhatIf

# Optional decoy metadata refresh for AD / Entra identities
Update-F4keH0undDecoy -Identity <Identity> -Platform AD -ObjectType User -Description "Incident refresh context" -WhatIf
Update-F4keH0undDecoy -Identity <Identity> -Platform Entra -ObjectType ServicePrincipal -Description "Incident refresh context" -WhatIf
```

---

## 3) Investigation Checklist (Both Severities)

1. Correlate trigger event with raw telemetry source payload.
2. Verify token correlation status (`TokenCorrelationStatus`).
3. Confirm actor identity and host context.
4. Determine whether the decoy was targeted manually or via automated discovery.
5. Build impact scope (identity plane, endpoint plane, Entra blast radius).
6. Record ATT&CK mapping and detection effectiveness notes.

---

## 4) Redesign and Recovery Workflow

After containment, rotate lure material and redeploy/refine decoy context.

```powershell
# Drift-first redesign list
Test-F4keH0undDrift -Source Events -AsList |
    Where-Object Drifted |
    Sort-Object DriftScore -Descending |
    Select-Object Identity, DriftSeverity, DriftReasons, SuggestedCommand

# Token material rotation example
Update-F4keH0undElement -ElementId <ElementId> -TemplateData @{ CanaryToken = 'fhlg-rotated-<unique>' } -WhatIf
```

Recovery exit criteria:

- Containment verified complete.
- Updated decoy/token artifacts deployed successfully.
- Detection and telemetry coverage confirmed.
- Incident summary completed and approved.

---

## 5) Communications Template

**Incident Title:** Token Trigger - `<Severity>` - `<Identity/Host>`

**Summary:**
At `<time>`, a `<severity>` token-trigger alert was detected by F4keH0und. Initial scope indicates `<scope>`. Current containment status: `<status>`.

**Next Update:** `<time>`

**Owners:**

- Incident Commander: `<name>`
- Detection Engineer: `<name>`
- Identity Platform Owner: `<name>`

---

## 6) Auto-Generate Playbook Files

Use repository utility script:

```powershell
./scripts/New-TokenTriggerResponsePlaybook.ps1 -AlertSeverity High
./scripts/New-TokenTriggerResponsePlaybook.ps1 -AlertSeverity Critical -Source Events -PreferSnapshot
```

By default the script writes to:

- `Docs/Playbooks/TokenTrigger-High-<Timestamp>.md`
- `Docs/Playbooks/TokenTrigger-Critical-<Timestamp>.md`

The generated markdown includes:

- severity SLA block,
- current matching findings from inventory,
- redesign suggestions (when drift recommendations are available),
- investigation and communications sections.
