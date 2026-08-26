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
- `custom_version` — required when `bump_type=custom` (for example `2.20.0`)
- `target_branch` — branch to version from (default: `main`)
- `create_tag` — create `vX.Y.Z` tag
- `create_release` — create GitHub Release from tag (auto-generated notes)

What it does:

1. Reads current `ModuleVersion` from `F4keH0und.psd1`.
2. Computes next semantic version (`X.Y.Z`).
3. Updates `F4keH0und.psd1` `ModuleVersion`.
4. Commits and pushes the version bump.
5. Optionally creates/pushes annotated tag `vX.Y.Z`.
6. Optionally creates a GitHub Release for that tag.

---

## Recommended Usage

### Patch release (default)

1. Open **Actions** → **Version and Release**.
2. Choose:
   - `bump_type = patch`
   - `target_branch = main`
   - `create_tag = true`
   - `create_release = true`
3. Run workflow.

### Minor/major release

Use `bump_type = minor` or `major` with the same defaults.

### Exact release version

Use `bump_type = custom` and set `custom_version` (for example `2.20.0`).

---

## Safety Notes

- The workflow fails if requested tag already exists.
- `custom_version` must be valid semantic version (`X.Y.Z`).
- If `create_release=true`, set `create_tag=true`.
- Version bump commit is created by `github-actions[bot]`.

---

## Local Equivalent (Manual Fallback)

If you need to release manually:

```powershell
# 1) Update ModuleVersion in F4keH0und.psd1

# 2) Commit
git add F4keH0und.psd1
git commit -m "chore(version): bump module to 2.20.0"

# 3) Tag + push
git tag -a v2.20.0 -m "F4keH0und - Last Generation v2.20.0"
git push origin main
git push origin v2.20.0
```

