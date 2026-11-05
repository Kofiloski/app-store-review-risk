---
summary: Explain review coverage, current-policy sourcing, privacy boundaries, and scanner limitations.
read_when:
  - Interpreting an App Review risk finding or unavailable policy source
  - Checking supported platforms, scan boundaries, or privacy behavior
---

# Review scope and limitations

`app-store-review-risk` combines a deterministic static scanner with an agent review workflow. It checks Apple-platform source, project settings, metadata, privacy declarations, entitlements, StoreKit flows, account handling, and submission artifacts without pretending that a heuristic can guarantee approval.

For every agent review, the skill retrieves Apple's live App Review Guidelines and latest official update notice, reads applicable sections and exceptions, and records the retrieval date separately from Apple's revision date. If sources are unavailable, it discloses the gap and leaves dependent policy conclusions as `Needs Verification`. The static scanner itself does not fetch policy updates; its output is evidence to investigate rather than proof of compliance with the latest rules.

**Private by design:** the default static scanner has no network integration and does not upload source code or findings. Optional `--xcodebuild` mode invokes the repository's local Xcode tooling and is subject to that project's package-resolution behavior. When used in GitHub Actions, the scanner runs inside the workflow runner under that repository's normal GitHub Actions controls.

## Why It Is More Than a Checklist

- **Deterministic first pass:** the CLI produces stable finding IDs and exact evidence before an agent reasons about context.
- **Target-aware:** scope source, plist, privacy manifest, and generated build-setting checks to the Xcode target being submitted.
- **Diff-aware:** separate new, changed-file, and resolved risks so existing unrelated findings do not automatically block a pull request.
- **Apple-platform aware:** cover iOS, iPadOS, macOS, Mac Catalyst, watchOS, tvOS, visionOS, TestFlight, and notarization paths.
- **Agent-ready:** compact text and JSON formats keep the first pass small while platform references support deeper review only where needed.
- **Current policy sources:** the skill checks live guidance, including relevant changes the scanner may not recognize, and cites the official sections supporting policy findings.

## What It Covers

- `Info.plist` permission descriptions and generated plist build settings
- `PrivacyInfo.xcprivacy`, required-reason APIs, tracking, and privacy collection clues
- entitlements, StoreKit, subscriptions, restore paths, and external purchase language
- Guideline 4.8 login-option signals, account deletion, and UGC moderation clues
- private API and placeholder-content signals
- App Store Connect artifact gaps such as screenshots, review notes, privacy answers, support URLs, and demo access
- multiple app targets, tests, extensions, examples, admin tools, and synchronized Xcode groups

## Important Notice

This tool cannot guarantee App Store, TestFlight, or notarization approval. Apple documentation, App Store Connect configuration, and App Review remain the source of truth.

For every agent review, retrieve the current App Review Guidelines and latest official update notice, then verify policy-dependent conclusions against the applicable live sections:

- [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [Apple Developer News](https://developer.apple.com/news/) for the latest guideline-update notice
- [Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines)
- relevant Apple Developer documentation and App Store Connect help

External purchase and account links remain storefront-specific. Guideline 4.8 describes the privacy outcomes required of an equivalent login option rather than naming a single mandatory identity provider. The scanner deliberately reports these change-prone areas as items to verify, not automatic policy verdicts.

## Limitations

- Static heuristics can produce false positives or miss behavior behind runtime configuration, remote services, feature flags, or App Store Connect-only setup.
- Symbolic links are not followed, so linked source outside the scanned tree needs separate review.
- A repository cannot prove privacy answers, subscription products, entitlement approval, backend availability, or reviewer credentials unless those artifacts are present.
- The source scanner does not inspect compiled `.ipa` or `.xcarchive` binaries.

The skill source procedure is [current-policy.md](../skills/app-store-review-risk/references/current-policy.md); platform-specific reference material lives in the same skill bundle.
