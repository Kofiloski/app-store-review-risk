# App Store Connect Artifacts

Use when repository evidence is not enough to prove review readiness. Many App Review rejections come from missing metadata, inaccessible flows, or mismatches between App Store Connect and app behavior.

## Required Review Inputs

- App Store Connect metadata: name, subtitle, description, keywords, category, age rating, support URL, marketing URL, privacy policy URL, and copyright.
- Screenshots and previews for every submitted platform, device class, localization, and major gated flow.
- App Privacy answers aligned with code, SDKs, analytics, tracking, collected data, linked data, and privacy manifests.
- Review notes explaining non-obvious features, hardware needs, sample data, region limits, entitlement approvals, and in-app purchase flows.
- Demo account or full-featured demo mode for account-based apps.
- Subscription/in-app purchase products, pricing, review screenshots, restore path, and cancellation/management explanation.
- Legal/regulatory evidence for health, finance, crypto, gambling, VPN, kids, education, AI, or region-restricted features.

## Suppression File

Use `.appstore-review-risk.yml` only for documented false positives. Keep reasons review-oriented, not just "ignore".

```yaml
suppressions:
  - id: storekit-external-purchase-language
    reason: "String is present only in internal admin tooling and is not shipped in the submitted app target."
```

Suppression IDs come from the scanner's markdown or JSON output. Do not suppress missing legal, privacy, purchase, or safety evidence unless the replacement evidence is named in the reason.
