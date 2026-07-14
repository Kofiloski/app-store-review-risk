# iOS and iPadOS Review Focus

Use after the target matrix identifies an iOS or iPadOS app target.

## Apply First

- App Review Guidelines globally, especially Safety, Performance, Business, Design, and Legal.
- Human Interface Guidelines for iOS/iPadOS touch, multitasking, adaptive layout, navigation, controls, accessibility, keyboard, pointer, and Apple platform conventions.
- Developer docs for privacy manifests, required-reason APIs, protected resources, StoreKit, Sign in with Apple, App Tracking Transparency, and background modes.

## Review Closely

- Permission purpose strings must be specific and tied to visible features.
- App Privacy answers and `PrivacyInfo.xcprivacy` must match SDKs, analytics, tracking, and required-reason API use.
- StoreKit must handle purchase, current entitlement, restore, subscription state, refunds/cancellation information, and review notes.
- External purchase/account links require storefront-specific review. United States storefront apps currently do not need the external-purchase-link entitlements for buttons, links, or calls to action; other storefronts may require an entitlement, region eligibility, disclosures, or may prohibit steering.
- Third-party/social login for a primary account needs an equivalent privacy-preserving login option under Guideline 4.8 unless an exception applies; do not reduce this check to provider-name detection alone.
- Account creation requires an easy-to-find in-app way to initiate deletion of the full account and associated data. If completion occurs on the web, link directly to that page; ordinary apps should not require a generic support flow.
- UGC requires filtering, reporting, blocking, abuse response, contact information, and reviewer-accessible test content.
- iPadOS apps need adaptive layout, multitasking behavior, keyboard/pointer ergonomics, and no phone-only stretched UI unless the target intentionally excludes iPad.
- Background modes, push notifications, location, Bluetooth, camera, microphone, photos, health, contacts, calendar, local network, and NFC must map to obvious user-facing value.

## Common Missing Evidence

- Demo credentials or demo mode.
- App Privacy answers.
- Review notes for non-obvious flows.
- Subscription product screenshots/configuration.
- Account deletion proof.
- UGC moderation policy.
