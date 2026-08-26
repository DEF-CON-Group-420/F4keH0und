# Documentation Index

All project documentation (except the main `README.md`) is stored in the `Docs/` directory.

## Documentation Policy

- Every code or behavior change must include corresponding documentation updates.
- Every change set must increment `ModuleVersion` in `F4keH0und.psd1` and append an entry to `Docs/changelog.md`.
- Keep architecture, examples, and roadmap documents aligned with the current implementation.
- Keep `COMMAND-REFERENCE.md` aligned whenever command names, parameters, defaults, or lifecycle behavior change.
- CI enforces command coverage via `scripts/Test-CommandReferenceCoverage.ps1`.
- CI enforces version/changelog policy via `scripts/Test-VersionChangelogPolicy.ps1`.
- If a feature is added, changed, or removed, update the relevant file(s) in `Docs/` in the same change set.

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) — Module internals, data-flow diagrams, design decisions, extension points.
- [EXAMPLES.md](EXAMPLES.md) — End-to-end deployment and operations examples.
- [RESPONSE-PLAYBOOKS.md](RESPONSE-PLAYBOOKS.md) — High/Critical token-trigger incident response templates and workflow.
- [TELEMETRY-CONNECTORS.md](TELEMETRY-CONNECTORS.md) — SIEM/SOAR connector preset model and payload mapping.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution workflow and standards.
- [VERSIONING.md](VERSIONING.md) — GitHub Actions version bump, tagging, and release workflow.
- [changelog.md](changelog.md) — Append-only change history with versioned release notes.
- [LAST-GENERATION-ROADMAP.md](LAST-GENERATION-ROADMAP.md) — Strategic phased plan.
- [COMMAND-REFERENCE.md](COMMAND-REFERENCE.md) — Full command catalog with parameters, meanings, behaviors, and examples.
