# App Store Review Risk

`app-store-review-risk` is a Codex skill and static scanner for reviewing Apple-platform app repositories before App Store, TestFlight, or notarization submission.

It helps identify likely review-risk areas in code, configuration, metadata, privacy declarations, StoreKit usage, entitlements, account flows, user-generated content, and platform-specific UX expectations.

## Important Notice

This tool does not guarantee App Store approval, TestFlight approval, or notarization acceptance. It is only intended to help teams find possible issues earlier and prepare a cleaner submission.

Always verify decisions against Apple's official documentation and current requirements:

- App Review Guidelines: https://developer.apple.com/app-store/review/guidelines/
- Human Interface Guidelines: https://developer.apple.com/design/human-interface-guidelines
- Apple Developer Documentation and App Store Connect guidance for platform-specific implementation, privacy, metadata, entitlement, and distribution requirements

Treat scanner findings as review leads, not final policy determinations. Apple Review, Apple documentation, and App Store Connect configuration remain the source of truth.

## What It Covers

- iOS and iPadOS apps
- macOS apps, Mac Catalyst apps, helpers, sandboxing, and notarization paths
- watchOS, tvOS, and visionOS apps
- `Info.plist`, entitlements, `PrivacyInfo.xcprivacy`, StoreKit, subscriptions, permissions, tracking, Sign in with Apple, account deletion, and UGC risk signals
- App Store Connect artifact gaps such as screenshots, review notes, privacy answers, support URLs, and demo access
- Target-aware scanning for projects with tests, extensions, examples, admin tools, or multiple app targets

## Install the CLI

With `pipx`:

```bash
pipx install git+https://github.com/Kofiloski/app-store-review-risk.git
```

With `pip`:

```bash
python3 -m pip install git+https://github.com/Kofiloski/app-store-review-risk.git
```

From a local clone:

```bash
python3 -m pip install .
```

After installation, run:

```bash
app-store-review-risk --help
```

## Install as a Codex Skill

Clone this repository into a Codex skills directory:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
git clone https://github.com/Kofiloski/app-store-review-risk.git "${CODEX_HOME:-$HOME/.codex}/skills/app-store-review-risk"
```

Then ask Codex to use the skill:

```text
Use $app-store-review-risk to review this Apple app repo before submission.
```

Other AI agents can still use the repository by reading `SKILL.md` and running the CLI or source-checkout wrapper directly.

## Run the Scanner

After installing the CLI:

```bash
app-store-review-risk /path/to/apple-app
```

Compact JSON output:

```bash
app-store-review-risk /path/to/apple-app --format compact-json
```

Scope code-pattern findings to a submitted Xcode target:

```bash
app-store-review-risk /path/to/apple-app --submitted-target MyApp
```

Use `xcodebuild` for more exact target metadata when the project can build or list schemes locally:

```bash
app-store-review-risk /path/to/apple-app --xcodebuild --scheme MyScheme
```

Review only risks introduced or touched by a Git diff:

```bash
app-store-review-risk /path/to/apple-app --diff origin/main...HEAD
```

Compare an older release to the current working tree:

```bash
app-store-review-risk /path/to/apple-app --base-ref v1.2.0
```

Compare two committed refs:

```bash
app-store-review-risk /path/to/apple-app --base-ref v1.2.0 --head-ref v1.3.0
```

For CI-style checks:

```bash
app-store-review-risk /path/to/apple-app --fail-on high
```

In diff mode, `--fail-on` applies to new findings and existing findings whose evidence touches changed files, so pre-existing unchanged findings do not fail a PR-style check.

From a source checkout without installing:

```bash
scripts/scan_apple_app_review_risks.py /path/to/apple-app
```

## Output Formats

- `compact` is the default, optimized for low token use.
- `compact-json` is structured and still token-conscious.
- `markdown` is useful for manual review reports.
- `json` includes the full scanner result for automation.

Inspect the cited files and App Store Connect artifacts before treating a result as a real rejection risk.

## Diff Mode

Diff mode scans the base version from Git without checking it out, then scans either the current working tree or a supplied head ref. It reports:

- `new_findings`: risk signals present in the head version but not the base version
- `changed_file_findings`: pre-existing findings whose current evidence references changed files
- `resolved_findings`: findings present in the base version but no longer present in the head version

Use `--diff <range>` for common Git ranges such as `origin/main...HEAD`. Use `--base-ref <ref>` when comparing a release tag to the current working tree.

## Skill Layout

- `SKILL.md`: agent workflow, reporting format, and review discipline
- `pyproject.toml`: Python package metadata and console script entry point
- `src/app_store_review_risk/`: installable CLI package
- `scripts/scan_apple_app_review_risks.py`: source-checkout compatibility wrapper
- `references/`: platform-specific review-risk notes loaded only when needed
- `agents/openai.yaml`: skill display metadata

## Limitations

- The scanner is heuristic and may produce false positives or miss behavior hidden behind runtime configuration, remote services, feature flags, or App Store Connect-only setup.
- Current Apple policy should be checked before making high-impact conclusions.
- Repository scans cannot prove metadata, privacy answers, subscription products, entitlement approvals, backend availability, or demo credentials unless those artifacts are present in the repo.

## Validate

```bash
python3 -m unittest tests/test_scanner.py
python3 /path/to/skill-creator/scripts/quick_validate.py .
```
