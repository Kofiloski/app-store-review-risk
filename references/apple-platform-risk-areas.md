# Apple Platform Review Risk Areas

Use this reference as a manual review checklist after running the scanner. Confirm current details against official Apple docs when a finding depends on a changing rule.

Priority sources:

- App Review Guidelines are the primary authority for likely rejection risk: https://developer.apple.com/app-store/review/guidelines/
- Human Interface Guidelines are the supporting authority for design, platform convention, accessibility, interaction, and UX-quality risks: https://developer.apple.com/design/human-interface-guidelines
- Developer documentation is the supporting authority for framework, entitlement, privacy manifest, and StoreKit implementation details.

When the App Review Guidelines and HIG both apply, anchor the rejection concern in App Review and use HIG to explain the design or usability gap.

## Target Discovery Before Guideline Selection

Build a target matrix before evaluating risks:

- **Target/scheme**: Xcode target or scheme being submitted.
- **Bundle identifier and product type**: app, extension, watch app, tvOS app, macOS app, visionOS app, companion app, or notarized iOS/iPadOS app.
- **Platform evidence**: `SDKROOT`, `SUPPORTED_PLATFORMS`, `TARGETED_DEVICE_FAMILY`, `UIDeviceFamily`, product type, deployment target, platform-specific imports, and App Store Connect destination if available.
- **Submission path**: App Store, TestFlight/App Review, macOS App Store, notarization, alternative marketplace, or web distribution.
- **Guideline set**: App Review Guidelines for every submitted app; HIG and developer docs narrowed to the identified platform and interaction model.

Do not report watchOS, tvOS, macOS, or visionOS issues solely because shared Swift code contains ambiguous APIs. Require target evidence or mark the item as `Needs Verification`.

After the target matrix is built, load the matching one-level reference file:

- `ios-ipados.md`
- `macos.md`
- `watchos.md`
- `tvos.md`
- `visionos.md`
- `app-store-connect-artifacts.md`

## Core App Review Surfaces

- **App completeness and reviewer access**: crash-free release build, no placeholder content, complete metadata, live backend, full demo account or full-featured demo mode, hardware/sample data available when needed.
- **Metadata accuracy**: screenshots, descriptions, age rating, category, privacy labels, subscription descriptions, pricing, support URL, marketing claims, and review notes must match app behavior.
- **Design and platform conventions**: confusing navigation, broken gestures, inaccessible controls, misleading system UI, nonstandard purchase flows, poor keyboard/remote/watch interactions, or UI that disregards Human Interface Guidelines can strengthen an App Review concern even when the code is technically functional.
- **Permissions**: every protected resource must have a specific, user-facing purpose string. Vague text such as "needed for app functionality" is a review risk.
- **Privacy manifests**: `PrivacyInfo.xcprivacy` files must be valid and aligned with collected data and required-reason API use. Invalid keys or values can fail App Store Connect processing before human review.
- **Tracking and ATT**: IDFA, tracking SDKs, cross-app/site tracking, and `ATTrackingManager` use require App Privacy alignment and a clear `NSUserTrackingUsageDescription`.
- **Entitlements**: capabilities such as HealthKit, HomeKit, iCloud, CloudKit, Apple Pay, CarPlay, Network Extension, DriverKit, VPN, multicast, critical alerts, family controls, and StoreKit external purchase need visible feature justification and sometimes Apple approval.
- **Payments and subscriptions**: digital goods and subscriptions generally need StoreKit. Review restore purchases, subscription management, cancellation information, product visibility, review notes, and fallback behavior.
- **External purchase/account links**: external purchase links, external account management links, and custom purchase links are storefront- and region-sensitive. Current App Review Guidelines allow buttons, external links, and other calls to action in United States storefront apps without the StoreKit external-purchase-link entitlements; other storefronts and special app categories can still require an entitlement, disclosure flow, or prohibit steering. Verify the current rule for every enabled storefront instead of assuming one global path.
- **Equivalent login option**: apps offering third-party or social login for the primary account need another equivalent login service that satisfies Guideline 4.8's privacy outcomes unless an exception applies. Sign in with Apple is a common implementation, but review the outcome and applicable exceptions rather than treating one provider name as the rule.
- **Account deletion**: apps that allow account creation must let users initiate full account deletion within the app. Completion may continue on a directly linked web page, and highly regulated apps may use additional customer-service confirmation, but a generic support-only path is not sufficient for ordinary apps.
- **User-generated content**: content posting, profiles, messaging, comments, reviews, or sharing features need reporting, blocking, moderation, abuse contact, and content filtering appropriate to the risk.
- **Regulated domains**: health, medical, finance, lending, crypto, gambling, VPN, kids, education, dating, alcohol, cannabis, firearms, legal advice, and AI-generated content may need extra disclaimers, licenses, safeguards, geographic restrictions, or review notes.
- **Background behavior**: background modes, push notifications, location, Bluetooth, audio, VoIP, and background processing must correspond to clear user-facing features.
- **Private APIs and hidden behavior**: private selectors, dynamic calls to private frameworks, obfuscated behavior, hidden debug menus, and feature flags that expose unreviewed behavior are high risk.

## Platform Notes

- **iOS/iPadOS/visionOS**: highest scrutiny for privacy strings, ATT, external purchases, account deletion, UGC, subscriptions, location, background modes, and app completeness.
- **macOS**: review sandboxing, hardened runtime, notarization expectations, file access, login items, helper tools, network extensions, auto-updaters, and external purchase/account flows.
- **watchOS**: review companion-app dependencies, health data, background refresh, complications, workout sessions, and accurate standalone capability claims.
- **tvOS**: review account/login ergonomics, subscriptions, media entitlements, privacy labels, top-shelf content, and remote-friendly navigation.

## Artifacts To Request When Missing

- App Store Connect metadata, screenshots, age rating, privacy nutrition labels, and review notes.
- In-app purchase/subscription product configuration and review screenshots.
- Entitlement approval records for restricted capabilities.
- Demo account credentials, sample data, backend environment, hardware requirements, or test QR codes.
- Legal/regulatory evidence for medical, finance, gambling, crypto, VPN, kids, or region-restricted features.
- Privacy policy, support URL, account deletion URL or in-app flow recording, and moderation policy for UGC apps.
