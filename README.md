# App Store Review Risk

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-View_Action-blue?logo=github)](https://github.com/marketplace/actions/app-store-review-risk)
[![CI](https://github.com/Kofiloski/app-store-review-risk/actions/workflows/ci.yml/badge.svg)](https://github.com/Kofiloski/app-store-review-risk/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/Kofiloski/app-store-review-risk)](https://github.com/Kofiloski/app-store-review-risk/releases)
[![PyPI](https://img.shields.io/pypi/v/app-store-review-risk)](https://pypi.org/project/app-store-review-risk/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Kofiloski/app-store-review-risk/blob/main/LICENSE)
[![skills.sh](https://skills.sh/b/Kofiloski/app-store-review-risk)](https://skills.sh/Kofiloski/app-store-review-risk)

Find likely App Store rejection risks in an Apple app repository or pull request, with stable finding IDs and file-level evidence.

The local scanner checks privacy manifests, permissions, entitlements, StoreKit, account handling, and submission artifacts. The agent skill adds contextual review against Apple's current guidelines and latest update notice.

## Run a preflight

```bash
uvx app-store-review-risk . --submitted-target MyApp
```

For a persistent command, use `pipx install app-store-review-risk`. Python 3.10 or newer is required. [Installation, diff scans, output formats, and CI](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/usage.md).

## Use the agent skill

```bash
gh skill install Kofiloski/app-store-review-risk \
  app-store-review-risk@v0.3.3 --agent codex --scope user
```

Then ask:

```text
Use $app-store-review-risk to review this app's submitted target and current diff.
Verify risks against current Apple guidance and cite file evidence and sources.
```

The skill uses the open Agent Skills format. [Other installers](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/usage.md#agent-skill-installation).

## See a real finding

The checked-in [demo app](https://github.com/Kofiloski/app-store-review-risk/tree/main/examples/demo-app) intentionally uses the camera without its permission description. The scanner reports:

```text
- HIGH `permissions-missing-nscamerausagedescription`: Potential protected-resource use without NSCameraUsageDescription (medium)
  evidence: `Sources/CameraView.swift:4: _ = AVCaptureDevice.default(for: .video)`
```

[Reproduce the scan and view its complete output](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/usage.md#real-scanner-output).

## Scope and limits

The default scanner reads local source without network requests or uploads. Optional `--xcodebuild` mode uses the project's local Xcode tooling and may resolve packages. Static scanning works on Linux and macOS; Xcode mode requires macOS.

Findings are investigation leads, not approval predictions. The scanner does not inspect compiled binaries or establish App Store Connect/backend state. The skill retrieves current Apple policy for every review; unavailable policy sources leave dependent conclusions as `Needs Verification`.

## Documentation

| Need | Guide |
| --- | --- |
| Install, scan a target/diff, or use GitHub Actions | [Scanner usage](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/usage.md) |
| Understand coverage, policy sourcing, and limitations | [Review scope](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/review-scope.md) |
| Contribute, validate, or publish | [Development and releases](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/development.md) |
| Maintain the canonical skill and toolkit copy | [Skill maintenance](https://github.com/Kofiloski/app-store-review-risk/blob/main/docs/skill-maintenance.md) |

Companion tools: [UI Testability Contract](https://github.com/Kofiloski/ios-ui-testability-contract-skill) repairs XCUITest failures; [iOS AI UI Check](https://github.com/Kofiloski/ios-ai-ui-check) runs app-owned Simulator scenarios.

MIT licensed. [Agent discovery](https://github.com/Kofiloski/app-store-review-risk/blob/main/llms.txt) · [Citation metadata](https://github.com/Kofiloski/app-store-review-risk/blob/main/CITATION.cff).
