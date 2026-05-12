# tvOS Review Focus

Use after the target matrix identifies a tvOS app target.

## Apply First

- App Review Guidelines globally.
- Human Interface Guidelines for tvOS focus, remote navigation, top shelf, media playback, account entry, accessibility, and living-room interaction.
- Developer docs for media playback, subscriptions, top shelf, Game Controller, and TV app integrations when used.

## Review Closely

- All primary flows must work with the remote/focus engine; avoid touch-only or pointer-only assumptions.
- Login and account entry need TV-friendly ergonomics, code-based sign-in, or clear companion/web handoff.
- Media apps need appropriate playback controls, resume behavior, subscription access, content rights, and metadata accuracy.
- Subscriptions and digital purchases need StoreKit compliance and review notes for gated content.
- Top shelf content must be current, accurate, and not misleading.
- Avoid intrusive overlays, large persistent logos, or controls that distract from video content without user value.

## Common Missing Evidence

- Test account with entitlement to gated media.
- Subscription/product configuration.
- Media rights or region constraints when relevant.
- Top shelf screenshots and behavior notes.
- Remote navigation/accessibility verification.
