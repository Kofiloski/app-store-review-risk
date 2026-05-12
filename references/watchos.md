# watchOS Review Focus

Use after the target matrix identifies a watchOS app, WatchKit extension, complication, workout app, or companion dependency.

## Apply First

- App Review Guidelines globally.
- Human Interface Guidelines for watchOS glanceable interactions, Digital Crown, gestures, complications, notifications, accessibility, and small-screen layout.
- Developer docs for HealthKit, workouts, background refresh, complications, WatchConnectivity, and notification behavior.

## Review Closely

- Companion-app dependencies must be clear; standalone capability claims must match actual behavior.
- HealthKit and workout sessions require accurate purpose strings, privacy policy alignment, and user-visible health/workout value.
- Background refresh, extended runtime sessions, audio, location, and notifications must be justified by the watch experience.
- Complications and widgets must be useful, accurate, and not misleading or stale.
- Login, purchase, and account flows must be usable on watchOS or cleanly handed off to the companion app.
- Avoid dense UI, tiny tap targets, long forms, or interaction patterns that conflict with watchOS HIG expectations.

## Common Missing Evidence

- Companion-app review path.
- HealthKit permission purpose and privacy policy.
- Sample workout/health data for review.
- Complication screenshots and update behavior.
- Review notes for hardware or account requirements.
