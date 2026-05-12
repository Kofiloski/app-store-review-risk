---
name: app-store-review-risk
description: Review Apple-platform app repositories or Git diffs for likely App Store Review, Notarization Review, privacy, entitlement, in-app purchase, metadata, and policy rejection risks before submission. Use when Codex is asked to audit iOS, iPadOS, macOS, watchOS, tvOS, or visionOS code/configuration for App Store approval readiness, preflight a release or PR diff, inspect Info.plist, entitlements, PrivacyInfo.xcprivacy, StoreKit, subscriptions, Sign in with Apple, account deletion, UGC, permissions, tracking, or other Apple review-sensitive behavior.
---

# App Store Review Risk

Use this skill to produce a practical pre-submission risk review for Apple-platform apps. Do not guarantee approval. Flag plausible rejection surfaces, missing evidence, and reviewer questions with file-backed reasoning.

## Workflow

1. Identify the app target, platform targets, and submission path before evaluating risks.
   - Look for `.xcodeproj`, `.xcworkspace`, `Package.swift`, `Info.plist`, `.entitlements`, `PrivacyInfo.xcprivacy`, StoreKit files, App Store Connect metadata, review notes, screenshots, and release configuration.
   - Prefer `xcodebuild -list -json` and, when a scheme is known, `xcodebuild -showBuildSettings -scheme <scheme>` to identify app targets, bundle identifiers, SDK roots, supported platforms, and targeted device families.
   - If Xcode commands are unavailable, infer targets from `project.pbxproj`, `Info.plist`, `SUPPORTED_PLATFORMS`, `SDKROOT`, `TARGETED_DEVICE_FAMILY`, app extensions, package manifests, and platform-specific imports.
   - Create a target matrix before findings: target/scheme, bundle identifier, product type, platform(s), submission path, and evidence.
   - Do not apply every platform checklist blindly. Apply App Review Guidelines globally, then apply HIG and developer guidance for the identified platform(s): iOS/iPadOS, macOS, watchOS, tvOS, visionOS, and notarized iOS/iPadOS apps when present.

2. Run the static scanner when a repo path is available:

```bash
python3 /path/to/app-store-review-risk/scripts/scan_apple_app_review_risks.py /path/to/app/repo
```

The default scanner output is compact; use it first. Use `--submitted-target <target>` when the submitted Xcode target is known so code-pattern findings ignore files from other targets. For PR or release-delta reviews, use `--diff <range>` or `--base-ref <ref> [--head-ref <ref>]` to compare versions and prioritize new findings plus existing findings that touch changed files. Use `--xcodebuild --scheme <scheme>` when the repo can run Xcode commands and exact target metadata is needed. Use `--format markdown` or `--format json` only when drilling into specific finding IDs or feeding another tool. Use `--format compact-json` when structured output is needed but token budget matters. Treat scanner findings as leads, not verdicts.

3. Read `references/apple-platform-risk-areas.md` for the shared risk map, then read only the platform file(s) matching the target matrix:
   - `references/ios-ipados.md` for iOS/iPadOS apps and iOS apps distributed through notarization.
   - `references/macos.md` for macOS apps, Mac Catalyst targets, helper tools, sandboxing, or notarization.
   - `references/watchos.md` for watch apps, WatchKit extensions, complications, workouts, and companion dependencies.
   - `references/tvos.md` for tvOS apps, focus navigation, media, top shelf, and TV subscriptions.
   - `references/visionos.md` for visionOS windows, volumes, immersive spaces, comfort, spatial input, and privacy.
   - `references/app-store-connect-artifacts.md` when metadata, screenshots, privacy answers, review notes, subscription config, or suppression files are missing or need review.

4. Use Apple's official guidance as the evaluation baseline.
   - Treat App Review Guidelines as the primary source for rejection risk: https://developer.apple.com/app-store/review/guidelines/
   - Use Human Interface Guidelines for the identified platform's design, interaction, platform convention, accessibility, and UX-quality risks that can affect review: https://developer.apple.com/design/human-interface-guidelines
   - Use developer documentation for implementation-specific requirements, including privacy manifest files, required-reason APIs, StoreKit external purchase entitlements, and platform frameworks.
   - When sources overlap, prioritize the App Review Guidelines for rejection likelihood and cite HIG as supporting design/UX evidence.

5. Inspect code and configuration behind every high or medium scanner finding. Check whether the app has:
   - reviewer-accessible login/demo mode and live backend services
   - matching purpose strings for protected resources
   - privacy manifests and App Privacy answers aligned with actual collection/tracking
   - entitlements justified by visible app behavior
   - complete in-app purchase, restore, subscription, cancellation, and review-note paths
   - compliant external purchase/account-management links
   - Sign in with Apple parity when third-party/social login is offered
   - in-app account deletion for apps that allow account creation
   - moderation, reporting, blocking, and abuse handling for user-generated content
   - accurate metadata, screenshots, age rating, support URL, and review notes

## Token Discipline

- Start with compact scanner output and the target matrix; do not paste full JSON or full markdown into the final answer.
- Scope the scanner with `--submitted-target` when multiple Xcode targets exist, especially if the repo includes examples, admin tools, fixtures, or tests.
- For diff reviews, lead with `new_findings` and `changed_file_findings`; keep existing unchanged findings secondary unless they are blocking release readiness.
- Load only `apple-platform-risk-areas.md`, the platform reference(s) matching the target matrix, and `app-store-connect-artifacts.md` if metadata evidence is missing.
- Quote only the highest-value evidence lines for each reported risk. Use finding IDs to refer back to scanner output.
- Browse or cite Apple docs only for current high-risk or policy-sensitive conclusions; prefer the App Review Guidelines first, then HIG or implementation docs.

## Reporting Format

Lead with risks, not a generic summary. Use this structure:

```markdown
## Target Matrix
- <target/scheme>: <bundle id>, <platform(s)>, <submission path>, <evidence>

## Findings

### Blocking Risk: <title>
- Severity: Blocking Risk | Likely Review Risk | Needs Verification | Low Signal
- Confidence: High | Medium | Low
- Evidence: <file:line or config key>
- Likely reviewer concern: <short explanation>
- Recommended fix: <specific code/config/review-note action>

## Missing Evidence
- <metadata, screenshots, review notes, privacy answers, subscription config, or backend access not available in the repo>

## Scanner Notes
- <summarize scanner output and any false positives dismissed>
```

Use `Blocking Risk` only for issues likely to stop submission, such as crashes, inaccessible core flows, missing required permission strings, invalid privacy manifests, unresolved external purchase entitlement use, or missing account deletion where account creation exists. Use `Needs Verification` for policy areas that require current Apple guidance, App Store Connect configuration, legal context, or reviewer notes.

## Review Discipline

- Prefer concrete file references over broad assertions.
- Separate code/config findings from App Store Connect metadata gaps.
- Name likely guideline areas when useful, but avoid overfitting exact rule numbers unless checked against the current App Review Guidelines.
- Call out false positives from the scanner explicitly so the user knows they were considered.
- Use `.appstore-review-risk.yml` suppressions only when the repository documents why a scanner finding is not review-relevant; still mention important suppressed high-risk areas if the reason is weak.
- If the repository alone cannot prove compliance, state the exact artifact needed: review notes, App Privacy answers, subscription products, screenshots, entitlement approval, backend/demo credentials, or legal/regulatory documentation.
