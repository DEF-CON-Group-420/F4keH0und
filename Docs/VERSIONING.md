# Versioning and Releases

This project uses a GitHub Actions workflow for version bumps, tagging, and optional GitHub Release creation.

Workflow file:

- `.github/workflows/version-release.yml`

---

## Workflow: `Version and Release`

Trigger type:

- Manual (`workflow_dispatch`)

Inputs:

- `bump_type` — `patch`, `minor`, `major`, `custom`
- `custom_version` — required when `bump_type=custom` (for example `2.20.2`)
- `changelog_note` — required short summary appended to `Docs/changelog.md`
- `target_branch` — branch to version from (default: `main`)
- `create_tag` — create `vX.Y.Z` tag
- `create_release` — create GitHub Release from tag (auto-generated notes)

What it does:

1. Reads current `ModuleVersion` from `F4keH0und.psd1`.
2. Computes next semantic version (`X.Y.Z`).
3. Updates `F4keH0und.psd1` `ModuleVersion`.
4. Updates the version badge in `README.md`.
5. Appends a new version entry to `Docs/changelog.md`.
6. Commits and pushes the version bump.
7. Optionally creates/pushes annotated tag `vX.Y.Z`.
8. Optionally creates a GitHub Release for that tag.

---

## Mandatory Policy

For every change set in this repository:

1. `F4keH0und.psd1` `ModuleVersion` must be incremented.
2. `Docs/changelog.md` must receive an appended entry describing the change.

CI enforces this policy through `scripts/Test-VersionChangelogPolicy.ps1`.

---

## Recommended Usage

### Patch release (default)

1. Open **Actions** → **Version and Release**.
2. Choose:
   - `bump_type = patch`
   - `changelog_note = <short summary>`
   - `target_branch = main`
   - `create_tag = true`
   - `create_release = true`
3. Run workflow.

### Minor/major release

Use `bump_type = minor` or `major` with the same defaults.

### Exact release version

Use `bump_type = custom` and set `custom_version` (for example `2.20.2`), plus `changelog_note`.

---

## Safety Notes

- The workflow fails if requested tag already exists.
- `custom_version` must be valid semantic version (`X.Y.Z`).
- `changelog_note` is mandatory and appended to `Docs/changelog.md`.
- If `create_release=true`, set `create_tag=true`.
- Version bump commit is created by `github-actions[bot]`.

---

## Local Equivalent (Manual Fallback)

If you need to release manually:

```powershell
# 1) Update ModuleVersion in F4keH0und.psd1

# 2) Append new section in Docs/changelog.md

# 3) Commit
git add F4keH0und.psd1 Docs/changelog.md README.md
git commit -m "chore(version): bump module to 2.20.2"

# 4) Tag + push
git tag -a v2.20.2 -m "F4keH0und - Last Generation v2.20.2"
git push origin main
git push origin v2.20.2
```
