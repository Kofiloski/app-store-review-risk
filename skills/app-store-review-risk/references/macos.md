# macOS Review Focus

Use after the target matrix identifies a macOS, Mac Catalyst, helper-tool, or notarized distribution target.

## Apply First

- App Review Guidelines globally for Mac App Store submissions.
- Notarization requirements when the submission path is Developer ID, alternative distribution, or direct distribution.
- Human Interface Guidelines for macOS menus, windows, settings, keyboard shortcuts, pointer interactions, file dialogs, toolbar behavior, accessibility, and platform conventions.

## Review Closely

- Sandbox entitlements must match visible app behavior; file, downloads, user-selected file, Apple Events, network, camera, microphone, and automation access need clear justification.
- Hardened runtime, notarization, helper tools, login items, privileged helpers, daemons, and auto-updaters need current signing and review/notarization evidence.
- Mac Catalyst apps need native-feeling menu, window, keyboard, pointer, and document behavior where relevant.
- External purchase/account links and subscriptions need storefront-specific review when digital goods are involved. Verify the current App Review Guidelines and StoreKit guidance rather than assuming a single entitlement rule across storefronts.
- Apps that access files broadly need user intent through open/save panels, bookmarks, or documented entitlement use.
- Private APIs, method swizzling of system behavior, hidden automation, or bypassing system privacy controls are high risk.

## Common Missing Evidence

- Entitlement approval records.
- Notarization logs or signing explanation.
- Helper tool purpose and installation/removal notes.
- Privacy policy, support URL, and data collection disclosures.
- Review notes explaining non-obvious file/system integrations.
