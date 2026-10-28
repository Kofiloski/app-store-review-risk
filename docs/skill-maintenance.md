---
summary: Keep the canonical review skill, toolkit copy, and release metadata aligned while preserving the scanner's offline boundary.
read_when:
  - Updating the review skill or its policy references
  - Synchronizing the skill with ios-release-quality-toolkit
  - Releasing the GitHub Action or updating its Marketplace listing
---

# Review skill maintenance

`skills/app-store-review-risk/` is the canonical installable Agent Skill. The root `SKILL.md` forwards legacy direct-clone installations to it. Update the nested instructions, references, and UI metadata together; keep the root UI prompt aligned when its wording changes.

`ios-release-quality-toolkit` embeds a separate copy of this skill. A toolkit release does not update this repository or direct skill installations. When changes are made in either repository, compare the bundles, port the applicable guidance, run both repositories' checks, and publish the affected release tags. Keep scanner pins aligned with the standalone package version. Do not imply that publishing a bundle updates an already installed local copy.

The agent workflow fetches current Apple guidelines and the latest official update notice on every review. `references/current-policy.md` owns that procedure. The static CLI remains offline; neither its findings nor bundled references establish a current-policy baseline. Native Xcode tools can provide local observations but do not prove App Store Connect configuration or approval.

Run `./scripts/check-skill.sh`, `python3 scripts/check-release-version.py <tag>`, the skill-creator validator for the nested skill, and `docs-list . --strict`. The repository's version tag releases the skill and source on GitHub and dispatches the existing PyPI workflow for the CLI. Verify each channel separately; a published GitHub release does not establish successful PyPI publication.

Also verify the [GitHub Marketplace listing](https://github.com/marketplace/actions/app-store-review-risk) after an Action release. If the intended version is missing, edit that existing GitHub release, select **Publish this Action to the GitHub Marketplace**, confirm the categories, and save with **Update release**. Follow [GitHub's publishing instructions](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace), then confirm the public listing shows the intended version and links to this repository. A successful release workflow alone does not establish Marketplace publication. Documentation-only follow-ups do not require moving an existing release tag or publishing another package version.
