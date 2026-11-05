# Runtime evidence for a review risk

Use when static findings need confirmation through an actual reviewer-facing flow, such as account deletion, permission requests, restore UI, or a crash. Start with existing app-owned tests and available Xcode tools. Do not introduce a UI-test target, model provider, or instrumentation dependency merely to complete a source review.

## Scope the observation

Record the source revision, installed build/configuration, target and bundle identifier, Simulator or physical-device identity/runtime, locale, launch/data setup, reproduction time window, and requested outcome. Distinguish development settings, local StoreKit configuration, sandbox services, and production services. Confirm that observed behavior belongs to the target being reviewed.

Collect screenshots or a focused test result first. When the cause is unclear, inspect existing runner/console logs or collect a short app-filtered excerpt around the same action. Keep stderr and command failures visible. No relevant log entry can mean logging was unavailable, filtered, or redacted; it does not establish that a behavior never occurred.

## Check only the relevant state

Trace the implementation to its actual storage or backend contract before inspecting data. For a Simulator app, resolve the current container with `xcrun simctl get_app_container <UDID> <bundle-id> data`; app-group, keychain, and remote stores are separate surfaces. Scope reads to the pertinent key/file/record. Use a consistent database snapshot with a read-only source; for file copies, stop writers and retain matching SQLite WAL/SHM files when required. Do not collect entire containers, credentials, or personal accounts as routine review artifacts. Keep raw state local and share redacted excerpts only.

For persistence claims, compare the expected stored values with the UI after normal relaunch. A confirmation screen or local record cannot prove server-side account deletion, subscription entitlement, refund/renewal behavior, data retention, or external-service completion. Identify the missing backend, signed-device, or App Store Connect evidence explicitly.

## Preserve verification boundaries

- Simulator success does not verify hardware permissions, device entitlement enforcement, physical performance, production purchases, or App Store approval.
- A local `.storekit` transaction proves only the configured local test behavior. It does not verify App Store Connect products or a signed purchase journey.
- Debugger or Frida observations can explain runtime calls, but hooks and jailbreaks alter the environment. Label instrumented results and reproduce through the normal app path without hooks before drawing a release conclusion. Do not install or enable instrumentation as a default review step.
- A connection/access failure is an unavailable diagnostic, not a policy violation or a passing check. Do not reset user data, modify live stores, or broaden host permissions to complete a review.
- A runtime observation supports the particular behavior tested. Missing or contradictory submission/backend evidence remains `Needs Verification`; current Apple policy retrieval is still required.

Report expected versus observed behavior, the environment and time window, commands/tools, relevant artifact paths, and remaining evidence gaps. Keep optional diagnostics outside the scanner's execution and upload boundaries; never place raw state or credentials into planner context or public artifacts.
