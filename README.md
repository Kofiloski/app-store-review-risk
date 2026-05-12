# App Store Review Risk

`app-store-review-risk` is a Codex skill and static scanner for reviewing Apple-platform app repositories before App Store, TestFlight, or notarization submission.

It helps identify likely review-risk areas in code, configuration, metadata, privacy declarations, StoreKit usage, entitlements, account flows, user-generated content, and platform-specific UX expectations. It is a preflight aid, not an approval guarantee.

## What It Covers

- iOS and iPadOS apps
- macOS apps, Mac Catalyst apps, helpers, sandboxing, and notarization paths
- watchOS, tvOS, and visionOS apps
- `Info.plist`, entitlements, `PrivacyInfo.xcprivacy`, StoreKit, subscriptions, permissions, tracking, Sign in with Apple, account deletion, and UGC risk signals
- App Store Connect artifact gaps such as screenshots, review notes, privacy answers, support URLs, and demo access
- Target-aware scanning for projects with tests, extensions, examples, admin tools, or multiple app targets

The review workflow uses Apple's official guidance as the baseline:

- App Review Guidelines: https://developer.apple.com/app-store/review/guidelines/
- Human Interface Guidelines: https://developer.apple.com/design/human-interface-guidelines

## Install

Clone this repository into a Codex skills directory:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
git clone <repo-url> "${CODEX_HOME:-$HOME/.codex}/skills/app-store-review-risk"
```

Then ask Codex to use the skill:

```text
Use $app-store-review-risk to review this Apple app repo before submission.
```

Other AI agents can still use the repository by reading `SKILL.md` and running the scanner script directly.

## Run the Scanner

From this repository:

```bash
python3 scripts/scan_apple_app_review_risks.py /path/to/apple-app
```

Compact JSON output:

```bash
python3 scripts/scan_apple_app_review_risks.py /path/to/apple-app --format compact-json
```

Scope code-pattern findings to a submitted Xcode target:

```bash
python3 scripts/scan_apple_app_review_risks.py /path/to/apple-app --submitted-target MyApp
```

Use `xcodebuild` for more exact target metadata when the project can build or list schemes locally:

```bash
python3 scripts/scan_apple_app_review_risks.py /path/to/apple-app --xcodebuild --scheme MyScheme
```

For CI-style checks:

```bash
python3 scripts/scan_apple_app_review_risks.py /path/to/apple-app --fail-on high
```

## Output Formats

- `compact` is the default, optimized for low token use.
- `compact-json` is structured and still token-conscious.
- `markdown` is useful for manual review reports.
- `json` includes the full scanner result for automation.

Scanner findings are leads. Inspect the cited files and App Store Connect artifacts before treating a result as a real rejection risk.

## Skill Layout

- `SKILL.md`: agent workflow, reporting format, and review discipline
- `scripts/scan_apple_app_review_risks.py`: deterministic static scanner
- `references/`: platform-specific review-risk notes loaded only when needed
- `agents/openai.yaml`: skill display metadata

## Limitations

- The scanner is heuristic and may produce false positives or miss behavior hidden behind runtime configuration, remote services, feature flags, or App Store Connect-only setup.
- Current Apple policy should be checked before making high-impact conclusions. App Review Guidelines are the primary source for rejection likelihood; HIG is supporting design and UX evidence.
- Repository scans cannot prove metadata, privacy answers, subscription products, entitlement approvals, backend availability, or demo credentials unless those artifacts are present in the repo.

## Validate

```bash
python3 -m unittest tests/test_scanner.py
python3 /path/to/skill-creator/scripts/quick_validate.py .
```
