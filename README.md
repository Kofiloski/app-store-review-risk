# App Store Review Risk

[![CI](https://github.com/Kofiloski/app-store-review-risk/actions/workflows/ci.yml/badge.svg)](https://github.com/Kofiloski/app-store-review-risk/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/Kofiloski/app-store-review-risk)](https://github.com/Kofiloski/app-store-review-risk/releases)
[![PyPI](https://img.shields.io/pypi/v/app-store-review-risk)](https://pypi.org/project/app-store-review-risk/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Kofiloski/app-store-review-risk/blob/main/LICENSE)
[![skills.sh](https://skills.sh/b/Kofiloski/app-store-review-risk)](https://skills.sh/Kofiloski/app-store-review-risk)

Catch likely App Store rejection risks in an Xcode repository or pull request before Apple sees the build—locally, target-aware, and with file-level evidence an AI coding agent can verify and help fix.

`app-store-review-risk` combines a deterministic static scanner with an agent review workflow. It checks Apple-platform source, project settings, metadata, privacy declarations, entitlements, StoreKit flows, account handling, and submission artifacts without pretending that a heuristic can guarantee approval.

**Private by design:** the default static scanner has no network integration and does not upload source code or findings. Optional `--xcodebuild` mode invokes the repository's local Xcode tooling and is subject to that project's package-resolution behavior. When used in GitHub Actions, the scanner runs inside the workflow runner under that repository's normal GitHub Actions controls.

Part of an open-source Apple quality toolkit: [make the UI automation-ready](https://github.com/Kofiloski/ios-ui-testability-contract-skill), [exercise it in iOS Simulator with an AI planner](https://github.com/Kofiloski/ios-ai-ui-check), then preflight the release here.

## 30-Second Agent Preflight

Install the skill with the open Agent Skills CLI:

```bash
npx skills add https://github.com/Kofiloski/app-store-review-risk --skill app-store-review-risk
```

Or install it with GitHub CLI:

```bash
gh skill install Kofiloski/app-store-review-risk app-store-review-risk --agent codex --scope user
```

Then ask your coding agent:

```text
Review this iOS app before App Store submission. Check the submitted target and
current Git diff for privacy, permissions, StoreKit, account, metadata, and
other likely rejection risks. Use $app-store-review-risk and cite file evidence.
```

The public bundle lives at `skills/app-store-review-risk/`, matching its frontmatter name and the Agent Skills discovery convention. The bundle contains only agent instructions, UI metadata, and focused references; the CLI and GitHub Action remain versioned at the repository root. A root `SKILL.md` compatibility entry point remains for older direct-clone installs, while new installs should use the nested package.

## 30-Second CLI Preflight

```bash
uvx app-store-review-risk . --submitted-target MyApp
```

For a persistent command, run `pipx install app-store-review-risk`. The scanner is packaged for Python 3.10 and newer, and PyPI is the low-friction CLI channel; GitHub remains the canonical source for the Agent Skill, Action, release history, and development.

## Why GitHub and PyPI Are Separate

One version tag serves three related deliverables, but they are distributed through two channels:

- The GitHub release versions the Agent Skill in `skills/app-store-review-risk/`, the root composite action, and the source repository. Installing the skill with `gh skill install` or `npx skills add` does not involve PyPI.
- The PyPI workflow publishes only the optional `app-store-review-risk` Python CLI wheel and source distribution. It runs automatically when the GitHub release is published.

If Trusted Publisher setup was missing or PyPI was temporarily unavailable, manually dispatch `Publish to PyPI` from the `main` branch and enter the existing release tag. The workflow checks out that exact tag, verifies it matches all package version metadata, rebuilds it, and skips files PyPI already accepted. A manual retry never creates or replaces the GitHub release or Agent Skill.

For the first PyPI release, register a pending Trusted Publisher at <https://pypi.org/manage/account/publishing/> with project `app-store-review-risk`, owner `Kofiloski`, repository `app-store-review-risk`, workflow `publish-pypi.yml`, and environment `pypi`. These values must match exactly; no API token is stored in GitHub.

## Real Scanner Output

This finding comes from the checked-in [`examples/demo-app`](https://github.com/Kofiloski/app-store-review-risk/tree/main/examples/demo-app) fixture, not a mocked interface:

```text
# Apple App Review Risk Scan Summary

Target: `examples/demo-app`
Platforms: iOS (high), iPadOS (high)
Findings: HIGH=1, MEDIUM=0, LOW=1, INFO=0

- HIGH `permissions-missing-nscamerausagedescription`: Potential protected-resource use without NSCameraUsageDescription (medium)
  evidence: `Sources/CameraView.swift:4: _ = AVCaptureDevice.default(for: .video)`
```

Reproduce the complete output:

```bash
scripts/scan_apple_app_review_risks.py examples/demo-app --format compact --max-findings 4
```

The path is shortened in the README; [`examples/demo-output.txt`](https://github.com/Kofiloski/app-store-review-risk/blob/main/examples/demo-output.txt) contains the normalized complete result used by the test suite.

## Why It Is More Than a Checklist

- **Deterministic first pass:** the CLI produces stable finding IDs and exact evidence before an agent reasons about context.
- **Target-aware:** scope source, plist, privacy manifest, and generated build-setting checks to the Xcode target being submitted.
- **Diff-aware:** separate new, changed-file, and resolved risks so existing unrelated findings do not automatically block a pull request.
- **Apple-platform aware:** cover iOS, iPadOS, macOS, Mac Catalyst, watchOS, tvOS, visionOS, TestFlight, and notarization paths.
- **Agent-ready:** compact text and JSON formats keep the first pass small while platform references support deeper review only where needed.

## Run in GitHub Actions

The repository is a root composite action. This example checks only App Review risks introduced or touched by a pull request:

```yaml
name: App Store review risk

on:
  pull_request:

permissions:
  contents: read

jobs:
  preflight:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Kofiloski/app-store-review-risk@v0.3.1
        with:
          path: .
          submitted-target: MyApp
          diff: ${{ github.event.pull_request.base.sha }}...${{ github.sha }}
          fail-on: high
```

Static scans also work on Linux runners. Set `xcodebuild: true` only on a macOS runner, and provide `scheme`, `project`, or `workspace` when the repository needs explicit Xcode selection.

## What It Covers

- `Info.plist` permission descriptions and generated plist build settings
- `PrivacyInfo.xcprivacy`, required-reason APIs, tracking, and privacy collection clues
- entitlements, StoreKit, subscriptions, restore paths, and external purchase language
- Guideline 4.8 login-option signals, account deletion, and UGC moderation clues
- private API and placeholder-content signals
- App Store Connect artifact gaps such as screenshots, review notes, privacy answers, support URLs, and demo access
- multiple app targets, tests, extensions, examples, admin tools, and synchronized Xcode groups

## Install Options

With `pipx`:

```bash
pipx install app-store-review-risk
```

With `pip`:

```bash
python3 -m pip install app-store-review-risk
```

Run once without a persistent install:

```bash
uvx app-store-review-risk . --submitted-target MyApp
```

Install an immutable GitHub release directly:

```bash
pipx install "git+https://github.com/Kofiloski/app-store-review-risk.git@v0.3.1"
```

From a local clone:

```bash
python3 -m pip install .
```

Without installing:

```bash
scripts/scan_apple_app_review_risks.py /path/to/apple-app
```

## Scanner Commands

Scan an app repository:

```bash
app-store-review-risk /path/to/apple-app
```

Scope code and configuration findings to the submitted target:

```bash
app-store-review-risk /path/to/apple-app --submitted-target MyApp
```

Use Xcode for more exact target metadata:

```bash
app-store-review-risk /path/to/apple-app --xcodebuild --scheme MyScheme
```

Review risks introduced or touched by a Git diff:

```bash
app-store-review-risk /path/to/apple-app --diff origin/main...HEAD
```

Compare a release with the working tree or another committed ref:

```bash
app-store-review-risk /path/to/apple-app --base-ref v1.2.0
app-store-review-risk /path/to/apple-app --base-ref v1.2.0 --head-ref v1.3.0
```

Fail a CI job on new or changed high-severity findings:

```bash
app-store-review-risk /path/to/apple-app --diff origin/main...HEAD --fail-on high
```

Working-tree comparisons include non-ignored untracked files. In diff mode, `--fail-on` applies to new findings and existing findings whose evidence touches changed files, rather than every unchanged finding in the repository.

## Output Formats

- `compact` is the default and is optimized for release and agent triage.
- `compact-json` is structured while remaining token-conscious.
- `markdown` produces a human-readable review report.
- `json` includes the complete machine-readable scan result.

Treat findings as investigation leads. Inspect the cited source and App Store Connect configuration before treating a heuristic signal as a real rejection risk.

## Important Notice

This tool cannot guarantee App Store, TestFlight, or notarization approval. Apple documentation, App Store Connect configuration, and App Review remain the source of truth.

Always verify high-impact conclusions against current official guidance:

- [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines)
- relevant Apple Developer documentation and App Store Connect help

External purchase and account links remain storefront-specific. Guideline 4.8 describes the privacy outcomes required of an equivalent login option rather than naming a single mandatory identity provider. The scanner deliberately reports these change-prone areas as items to verify, not automatic policy verdicts.

## Repository Layout

- `skills/app-store-review-risk/SKILL.md`: published agent workflow, reporting format, and review discipline
- `skills/app-store-review-risk/agents/` and `skills/app-store-review-risk/references/`: skill UI metadata and focused platform guidance
- `src/app_store_review_risk/`: installable CLI package
- `action.yml` and `scripts/run-action.sh`: composite GitHub Action entry point
- `examples/demo-app/` and `examples/demo-output.txt`: reproducible scanner demonstration
- `llms.txt`: compact machine-readable repository map
- `CITATION.cff`: software citation metadata
- `scripts/check-skill.sh`: full local validation

## Limitations

- Static heuristics can produce false positives or miss behavior behind runtime configuration, remote services, feature flags, or App Store Connect-only setup.
- Symbolic links are not followed, so linked source outside the scanned tree needs separate review.
- A repository cannot prove privacy answers, subscription products, entitlement approval, backend availability, or reviewer credentials unless those artifacts are present.
- The source scanner does not inspect compiled `.ipa` or `.xcarchive` binaries.

## Validate

```bash
./scripts/check-skill.sh
```
