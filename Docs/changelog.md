# Changelog

All changes are recorded here.

Policy:

- Every change set must increment `ModuleVersion` in `F4keH0und.psd1` using semantic version progression (patch → minor → major).
- Every change set must append a new changelog entry to this file.
- New entries are append-only and should include version, date, and summary bullets.

---

## 2.20.2 - 2026-09-24

- Reverted release-facing version references and release examples to `2.20.2` across README, workflow metadata, and versioning docs to prepare a consistent `v2.20.2` release.
- Fixed Quick Start Step 2/3 documentation bug: `$bloodHoundPath = Join-Path $PWD 'BH_Data'` assumed a `BH_Data` folder that no install step creates, causing `Find-F4keH0undOpportunity`/`New-F4keH0undDecoy` to fail `BloodHoundPath` parameter validation on a fresh clone. Added guidance to point `-BloodHoundPath` at real unzipped collector output.
- Added "Lab Validation" section documenting an end-to-end test run against a live Ludus AD lab (PyroTek3/ADLab-seeded domain, SharpHound v2.16.0 collection, `Find-F4keH0undOpportunity`/`New-F4keH0undDecoy -WhatIf` analysis pass) with concrete opportunity counts and lab-specific findings (no `New-AADToken` cmdlet exists — real cmdlet is `New-F4keH0undToken`; Entra/hybrid parity goes through `Sync-F4keH0undEntraParity`).

## 2.20.1 - 2026-08-26

- Added CI-enforced policy validation for mandatory semantic version bump and changelog append (`scripts/Test-VersionChangelogPolicy.ps1`).
- Updated CI workflow to validate version/changelog policy on both `push` and `pull_request` events.
- Added governance documentation for mandatory version + changelog behavior.
