---
summary: Keep the canonical review skill, toolkit copy, and release metadata aligned while preserving the scanner's offline boundary.
read_when:
  - Updating the review skill or its policy references
  - Synchronizing the skill with ios-release-quality-toolkit
---

# Review skill maintenance

`skills/app-store-review-risk/` is the canonical installable Agent Skill. The root `SKILL.md` forwards legacy direct-clone installations to it. Update the nested instructions, references, and UI metadata together; keep the root UI prompt aligned when its wording changes.

`ios-release-quality-toolkit` embeds a separate copy of this skill. A toolkit release does not update this repository or direct skill installations. When changes are made in either repository, compare the bundles, port the applicable guidance, run both repositories' checks, and publish the affected release tags. Keep scanner pins aligned with the standalone package version. Do not imply that publishing a bundle updates an already installed local copy.

The agent workflow fetches current Apple guidelines and the latest official update notice on every review. `references/current-policy.md` owns that procedure. The static CLI remains offline; neither its findings nor bundled references establish a current-policy baseline. Native Xcode tools can provide local observations but do not prove App Store Connect configuration or approval.

Run `./scripts/check-skill.sh`, `python3 scripts/check-release-version.py <tag>`, the skill-creator validator for the nested skill, and `docs-list . --strict`. The repository's version tag releases the skill and source on GitHub and dispatches the existing PyPI workflow for the CLI. Verify each channel separately; a published GitHub release does not establish successful PyPI publication.
