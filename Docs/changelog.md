# Changelog

All changes are recorded here.

Policy:

- Every change set must increment `ModuleVersion` in `F4keH0und.psd1` using semantic version progression (patch → minor → major).
- Every change set must append a new changelog entry to this file.
- New entries are append-only and should include version, date, and summary bullets.

---

## 2.20.3 - 2026-09-24

- **Fixed BUG-001**: `New-F4keH0undDecoy -Execute` hung indefinitely on an unconditional `Read-Host` selection prompt (and a second `Read-Host` CSV-save prompt), making the flagship deployment workflow unusable in any non-interactive/automation context. Added `-All` and `-SelectId <string[]>` parameters to select opportunities non-interactively, and `-SaveReport`/`-NoReport` switches to control the CSV-save prompt without blocking.
- **Fixed BUG-002**: `Disable-F4keH0undElement` and `Enable-F4keH0undElement` always threw `Cannot convert value "PSCustomObject" to type "Hashtable"` because element state loaded via `ConvertFrom-Json` was passed directly into a strictly-typed `[hashtable]$State` parameter. Fixed by converting the loaded state to a real hashtable before persisting, using a PS 5.1-compatible manual property copy (avoids `ConvertFrom-Json -AsHashtable`, which requires PS 6+ and breaks under Windows PowerShell 5.1 remoting endpoints).
- **Fixed BUG-003**: The Create-mode fallback path in `New-F4keH0undDecoy` (used whenever no recyclable AD object exists for a given opportunity) called `New-PrivateADDecoyUser`, but that function had been renamed to `New-PrivateADDecoyUser.ps1.deprecated` during the recycling-first refactor and was no longer loaded by the module, so every Create-mode decoy deployment (`StaleAdminLure`, `KerberoastableUser`, `ACLAttackPath`, `UnconstrainedDelegationComputer` when nothing recyclable exists) failed with "term not recognized". Restored the file as `New-PrivateADDecoyUser.ps1` so the module loads it again; `Set-PrivateADDecoyUser` (recycle) remains the preferred path and is used automatically first.
- All three fixes verified live against a real Ludus AD lab: `-SelectId` selection completes without hanging or prompting; `Disable-F4keH0undElement`/`Enable-F4keH0undElement` succeed end-to-end (`Status: Disabled` / `Status: Armed`); Create-mode now reaches real `New-ADUser` execution instead of failing on a missing cmdlet.

## 2.20.2 - 2026-09-24

- Reverted release-facing version references and release examples to `2.20.2` across README, workflow metadata, and versioning docs to prepare a consistent `v2.20.2` release.
- Fixed Quick Start Step 2/3 documentation bug: `$bloodHoundPath = Join-Path $PWD 'BH_Data'` assumed a `BH_Data` folder that no install step creates, causing `Find-F4keH0undOpportunity`/`New-F4keH0undDecoy` to fail `BloodHoundPath` parameter validation on a fresh clone. Added guidance to point `-BloodHoundPath` at real unzipped collector output.
- Added "Lab Validation" section documenting an end-to-end test run against a live Ludus AD lab (PyroTek3/ADLab-seeded domain, SharpHound v2.16.0 collection, `Find-F4keH0undOpportunity`/`New-F4keH0undDecoy -WhatIf` analysis pass) with concrete opportunity counts and lab-specific findings (no `New-AADToken` cmdlet exists — real cmdlet is `New-F4keH0undToken`; Entra/hybrid parity goes through `Sync-F4keH0undEntraParity`).

## 2.20.1 - 2026-08-26

- Added CI-enforced policy validation for mandatory semantic version bump and changelog append (`scripts/Test-VersionChangelogPolicy.ps1`).
- Updated CI workflow to validate version/changelog policy on both `push` and `pull_request` events.
- Added governance documentation for mandatory version + changelog behavior.
