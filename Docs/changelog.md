# Changelog

All changes are recorded here.

Policy:

- Every change set must increment `ModuleVersion` in `F4keH0und.psd1` using semantic version progression (patch → minor → major).
- Every change set must append a new changelog entry to this file.
- New entries are append-only and should include version, date, and summary bullets.

---

## 2.20.1 - 2026-08-26

- Added CI-enforced policy validation for mandatory semantic version bump and changelog append (`scripts/Test-VersionChangelogPolicy.ps1`).
- Updated CI workflow to validate version/changelog policy on both `push` and `pull_request` events.
- Added governance documentation for mandatory version + changelog behavior.

