# Changelog

All changes are recorded here.

Policy:

- Every change set must increment `ModuleVersion` in `F4keH0und.psd1` using semantic version progression (patch → minor → major).
- Every change set must append a new changelog entry to this file.
- New entries are append-only and should include version, date, and summary bullets.

---

## 2.20.4 - 2026-09-25

- **Fixed CI automation bug**: The "must bump version + append changelog" policy check
  (`scripts/Test-VersionChangelogPolicy.ps1`, enforced via `.github/workflows/ci.yml`) was
  silently unusable in two independent ways — this is why the `2.20.2` version bump had to be
  applied manually:
  1. **Single sequential CI job**: the `PSScriptAnalyzer` lint step and the version/changelog
     policy step lived in the same job. When lint failed (even on a single low-severity finding),
     GitHub Actions skipped every subsequent step in that job by default — including the policy
     check — so the mandatory version-bump enforcement silently never ran. Split into two
     independent jobs (`lint` and `policy`) so a lint failure can never suppress policy
     enforcement again.
  2. **Lint failed on non-blocking findings**: `PSScriptAnalyzer`'s failure condition was
     `if ($results)`, meaning *any* finding of *any* severity (including `Information`-level
     trailing-whitespace notices) failed the whole build. Changed to only fail on `Error`-severity
     findings; `Warning`/`Information` findings are now printed for visibility but non-blocking.
  3. **Changelog "append-only" check assumed the wrong insertion point**: `Test-VersionChangelogPolicy.ps1`
     required `newContent.StartsWith(oldContent)` (pure end-of-file append), but this changelog's
     actual convention — used in every prior entry, including this one — inserts new entries
     newest-first, immediately after the leading `---` separator. That mismatch meant the policy
     check would fail on *every single correctly-formatted changelog update*, making the
     automation unusable by design rather than by accident. Fixed by validating that old content
     survives fully intact, split at exactly one insertion point anywhere in the file (via
     longest-common-prefix/suffix comparison), rather than assuming append happens only at the
     very start or very end.
- Also fixed a `PSScriptAnalyzer` `Error`-severity finding (`PSAvoidUsingConvertToSecureStringWithPlainText`)
  in `Private/New-PrivateADDecoyUser.ps1` introduced when that file was restored from
  `.ps1.deprecated` in `2.20.3`: the random decoy password is now built directly as a
  `SecureString` (character-by-character) instead of round-tripping through a plaintext
  `[string]`. Also added `SupportsShouldProcess` to the function per `PSUseShouldProcessForStateChangingFunctions`.
- Verified the fix by simulating the exact policy check against yesterday's real `2.20.3` push
  (`5af06dc..1fabfed`): it now correctly PASSES (previously would have thrown on both the
  skipped-job bug and the append-only-direction bug, if it had run at all). Also unit-verified the
  new splice-based append-only check against synthetic middle-insert, tampered-content, pure-append,
  and pure-prepend cases — tampering with existing entries is still correctly rejected.

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
