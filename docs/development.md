---
summary: Maintain the repository, validate changes, and publish the skill, Action, and Python package.
read_when:
  - Contributing to the scanner or locating its source and examples
  - Publishing or retrying GitHub and PyPI releases
---

# Development and releases

## Why GitHub and PyPI Are Separate

One version tag serves three related deliverables, but they are distributed through two channels:

- The GitHub release versions the Agent Skill in `skills/app-store-review-risk/`, the root composite action, and the source repository. Installing the skill with `gh skill install` or `npx skills add` does not involve PyPI.
- The PyPI workflow publishes only the optional `app-store-review-risk` Python CLI wheel and source distribution. It runs automatically when the GitHub release is published.

If Trusted Publisher setup was missing or PyPI was temporarily unavailable, manually dispatch `Publish to PyPI` from the `main` branch and enter the existing release tag. The workflow checks out that exact tag, verifies it matches all package version metadata, rebuilds it, and skips files PyPI already accepted. A manual retry never creates or replaces the GitHub release or Agent Skill.

Pushing an exact `vX.Y.Z` tag runs the repository-owned release workflow, which validates the tag, creates the GitHub release, and dispatches the PyPI workflow with GitHub's built-in token. Maintainers do not need to authorize GitHub CLI with personal or organization scopes.

For the first PyPI release, register a pending Trusted Publisher at <https://pypi.org/manage/account/publishing/> with project `app-store-review-risk`, owner `Kofiloski`, repository `app-store-review-risk`, workflow `publish-pypi.yml`, and environment `pypi`. These values must match exactly; no API token is stored in GitHub.

## Repository Layout

- `skills/app-store-review-risk/SKILL.md`: published agent workflow, reporting format, and review discipline
- `skills/app-store-review-risk/agents/` and `skills/app-store-review-risk/references/`: skill UI metadata and focused platform guidance
- `docs/skill-maintenance.md`: canonical skill location, toolkit synchronization, and verification boundaries
- `src/app_store_review_risk/`: installable CLI package
- `action.yml` and `scripts/run-action.sh`: composite GitHub Action entry point
- `examples/demo-app/` and `examples/demo-output.txt`: reproducible scanner demonstration
- `llms.txt`: compact machine-readable repository map
- `CITATION.cff`: software citation metadata
- `scripts/check-skill.sh`: full local validation

## Validate

```bash
./scripts/check-skill.sh
```

For canonical skill ownership, toolkit synchronization, and Marketplace checks, read [skill maintenance](skill-maintenance.md). Documentation-only changes do not require a new version or moving a published tag.
