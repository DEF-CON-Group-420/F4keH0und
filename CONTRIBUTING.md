# Contributing to F4keH0und

Thank you for your interest in F4keH0und! Contributions, bug reports, and feature suggestions are welcome.

## Forking the Repository

1. Click the **Fork** button at the top-right of the [repository page](https://github.com/DEF-CON-Group-420/F4keH0und).
2. Clone your fork locally:
   ```powershell
   git clone https://github.com/<your-username>/F4keH0und.git
   cd F4keH0und
   ```
3. Add the upstream remote so you can pull in future updates:
   ```powershell
   git remote add upstream https://github.com/DEF-CON-Group-420/F4keH0und.git
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
2. Follow the [Extending F4keH0und](README.md#-extending-f4keh0und) guide when adding new detection or decoy types.
3. Ensure your PowerShell code passes [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) before submitting:
   ```powershell
   Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
   Invoke-ScriptAnalyzer -Path . -Recurse
   ```

## Submitting a Pull Request

1. Push your branch to your fork:
   ```powershell
   git push origin feature/my-new-feature
   ```
2. Open a Pull Request against the `main` branch of the upstream repository.
3. Describe your changes and reference any related issues.

## Code Style

- Follow the existing PowerShell conventions in the repository (verb-noun function naming, `[CmdletBinding()]`, comment-based help).
- Keep private helper functions in the `Private\` directory and public API functions in `Public\`.
- Add or update the comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`) for any function you modify.
