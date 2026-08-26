# Contributing to F4keH0und - Last Generation

Thank you for your interest in F4keH0und - Last Generation! Contributions, bug reports, and feature suggestions are welcome.

## Forking the Repository

1. Click the **Fork** button at the top-right of the [repository page](https://github.com/th3r3d/F4keH0und-LG).
2. Clone your fork locally:
   ```powershell
   git clone https://github.com/<your-username>/F4keH0und-LG.git
   cd F4keH0und-LG
   ```
3. Add the upstream remote so you can pull in future updates:
   ```powershell
   git remote add upstream https://github.com/th3r3d/F4keH0und-LG.git
   ```

## Keeping Your Fork Up to Date

```powershell
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Making Changes

1. Create a new branch for your changes:
   ```powershell
   git checkout -b feature/my-new-feature
   ```
2. Follow the [Extending F4keH0und](../README.md#-extending-f4keh0und) guide when adding new detection or decoy types.
3. Increment `ModuleVersion` in `F4keH0und.psd1` for every change set using semantic versioning rules (`patch`/`minor`/`major`).
4. Append a new entry to `Docs/changelog.md` describing what changed.
5. Update the relevant files in `Docs/` for every code or behavior change (including `COMMAND-REFERENCE.md` when command parameters/behavior change).
6. Ensure your PowerShell code passes [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) before submitting:
   ```powershell
   Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
   Invoke-ScriptAnalyzer -Path . -Recurse
   ```
7. Validate command-reference coverage locally before pushing:
   ```powershell
   ./scripts/Test-CommandReferenceCoverage.ps1
   ```
8. Validate version/changelog policy locally before pushing:
   ```powershell
   ./scripts/Test-VersionChangelogPolicy.ps1 -BaseRef HEAD^ -HeadRef HEAD
   ```

## Submitting a Pull Request

1. Push your branch to your fork:
   ```powershell
   git push origin feature/my-new-feature
   ```
2. Open a Pull Request against the `main` branch of the upstream repository.
3. Describe your changes and reference any related issues.

## Versioning and Releases

Project versioning and release creation can be performed through GitHub Actions:

- Workflow: `Version and Release`
- File: `.github/workflows/version-release.yml`

Typical release flow:

1. Open **Actions** → **Version and Release**.
2. Choose bump type (`patch`, `minor`, `major`, or `custom`).
3. Provide `changelog_note` with a concise description of the release change set.
4. Keep `target_branch = main`.
5. Set `create_tag = true` and `create_release = true`.
6. Run workflow.

For full parameter details and behavior, see [VERSIONING.md](VERSIONING.md).

## Code Style

- Follow the existing PowerShell conventions in the repository (verb-noun function naming, `[CmdletBinding()]`, comment-based help).
- Keep private helper functions in the `Private\` directory and public API functions in `Public\`.
- Add or update the comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`) for any function you modify.
