# Current Apple policy check

Perform this check for each review before interpreting scanner results, including reviews limited to a PR or release delta. Reuse sources fetched during the same review; a new request to refresh the policy baseline needs a new retrieval. A scanner release, bundled checklist, search snippet, or previous report cannot establish the current rules.

## Retrieve and scope

1. Open the live [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/). Record the retrieval date and the page's displayed **Last Updated** date; do not infer Apple's revision date from a search crawl date or HTTP timestamp. If no revision date is displayed, say so.
2. Open the latest relevant guideline-update announcement from [Apple Developer News](https://developer.apple.com/news/). Follow the guidelines' revision link when available, or search Apple's official site and open the announcement itself. Compare publication dates rather than assuming the top search result is newest. The notice identifies changes to inspect; the current guidelines remain the evaluation baseline.
3. Read the live sections matching the app's platform, features, submission/distribution path, and storefronts, together with their exceptions. Review relevant changes named in the announcement even if the scanner has no matching rule. For a diff review, prioritize changed surfaces and newly applicable policy risks without expanding into an unrelated full audit.
4. Verify linked Apple implementation or entitlement requirements when the conclusion depends on them. Check [Upcoming Requirements](https://developer.apple.com/news/upcoming-requirements/) for submission deadlines relevant to the requested release. Separate currently effective rules from announced future requirements; do not report a future deadline as an existing violation.
5. Attach the official section URL and applicable conditions to policy-dependent findings. Distinguish the code/config evidence from the policy interpretation and any missing App Store Connect, backend, entitlement, or regional evidence. Do not overrule live wording with a rule number or assumption embedded in a scanner.

Use the current English text when an official translation lags a new revision. State material differences or uncertainty rather than treating the older translation as the latest policy. This source check does not change the app's localization requirements.

## Changing areas to verify when applicable

- UGC, random/anonymous chat, AI content generation, moderation, age restrictions, and child safety: inspect the current scope and safeguards rather than limiting UGC to uploaded posts.
- Metadata: distinguish app-in-use screenshots/previews from creative assets such as product-page headers and search assets. Apply each asset type's current rules.
- Hidden or undocumented features: trace feature flags, remotely enabled behavior, demo/reviewer differences, and disclosure in review notes. A flag alone is not evidence of concealment.
- External purchases and account links: check the exact storefront, app category, destination, entitlement, distribution terms, and effective dates. Do not apply one region's permission or restriction globally.
- Data sharing, including third-party AI: inspect disclosure, permission, actual payloads, SDK behavior, and App Privacy answers against the current wording.

These are prompts for source selection, not an exhaustive policy snapshot or findings to emit without app evidence.

## If retrieval is unavailable

Continue inspecting code, configuration, and supplied artifacts. List which live sources could not be opened and any supplied snapshot's date. Label dependent policy conclusions `Needs Verification`; independently proven code defects can retain their evidence-backed severity. Do not infer that no policies changed, fabricate a revision date, or describe an offline review as current compliance verification. If a notice is unavailable but the guidelines are readable, use the live text and disclose the missing change-history check.

## Report the baseline

Include a compact `Policy Sources` section with the guidelines URL, retrieval date, Apple's displayed revision date, update-notice URL/date, relevant changes and applicability, and retrieval gaps. Cite the supporting official section next to each policy-dependent finding. No findings from a static scan is not proof of compliance with the current guidelines.
