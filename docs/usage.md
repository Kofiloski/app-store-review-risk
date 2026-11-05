---
summary: Install and run the review scanner locally or in GitHub Actions, with reproducible output examples.
read_when:
  - Choosing scanner installation, target scoping, or diff options
  - Configuring a GitHub Action or interpreting scanner output
---

# Scanner usage

## Agent skill installation

Install with the open Agent Skills CLI:

```bash
npx skills add https://github.com/Kofiloski/app-store-review-risk --skill app-store-review-risk
```

Or pin the GitHub skill release for Codex:

```bash
gh skill install Kofiloski/app-store-review-risk app-store-review-risk@v0.3.3 --agent codex --scope user
```

The public bundle lives at `skills/app-store-review-risk/`. It contains agent instructions, UI metadata, and focused references. A root `SKILL.md` remains for older direct-clone installations; new installs should use the nested bundle. The optional scanner CLI and GitHub Action are distributed separately, as described in [development and releases](development.md).

## Install Options

With `pipx`:

```bash
pipx install app-store-review-risk
```

With `pip`:

```bash
python3 -m pip install app-store-review-risk
```

Run once without a persistent install:

```bash
uvx app-store-review-risk . --submitted-target MyApp
```

Install an immutable GitHub release directly:

```bash
pipx install "git+https://github.com/Kofiloski/app-store-review-risk.git@v0.3.3"
```

From a local clone:

```bash
python3 -m pip install .
```

Without installing:

```bash
scripts/scan_apple_app_review_risks.py /path/to/apple-app
```

## Scanner Commands

Scan an app repository:

```bash
app-store-review-risk /path/to/apple-app
```

Scope code and configuration findings to the submitted target:

```bash
app-store-review-risk /path/to/apple-app --submitted-target MyApp
```

Use Xcode for more exact target metadata:

```bash
app-store-review-risk /path/to/apple-app --xcodebuild --scheme MyScheme
```

Review risks introduced or touched by a Git diff:

```bash
app-store-review-risk /path/to/apple-app --diff origin/main...HEAD
```

Compare a release with the working tree or another committed ref:

```bash
app-store-review-risk /path/to/apple-app --base-ref v1.2.0
app-store-review-risk /path/to/apple-app --base-ref v1.2.0 --head-ref v1.3.0
```

Fail a CI job on new or changed high-severity findings:

```bash
app-store-review-risk /path/to/apple-app --diff origin/main...HEAD --fail-on high
```

Working-tree comparisons include non-ignored untracked files. In diff mode, `--fail-on` applies to new findings and existing findings whose evidence touches changed files, rather than every unchanged finding in the repository.

## Output Formats

- `compact` is the default and is optimized for release and agent triage.
- `compact-json` is structured while remaining token-conscious.
- `markdown` produces a human-readable review report.
- `json` includes the complete machine-readable scan result.

Treat findings as investigation leads. Inspect the cited source and App Store Connect configuration before treating a heuristic signal as a real rejection risk.

## Run in GitHub Actions

The repository is a root composite action. This example checks only App Review risks introduced or touched by a pull request:

```yaml
name: App Store review risk

on:
  pull_request:

permissions:
  contents: read

jobs:
  preflight:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Kofiloski/app-store-review-risk@v0.3.3
        with:
          path: .
          submitted-target: MyApp
          diff: ${{ github.event.pull_request.base.sha }}...${{ github.sha }}
          fail-on: high
```

Static scans also work on Linux runners. Set `xcodebuild: true` only on a macOS runner, and provide `scheme`, `project`, or `workspace` when the repository needs explicit Xcode selection.

## Real Scanner Output

This finding comes from the checked-in [`examples/demo-app`](https://github.com/Kofiloski/app-store-review-risk/tree/main/examples/demo-app) fixture, not a mocked interface:

```text
# Apple App Review Risk Scan Summary

Target: `examples/demo-app`
Platforms: iOS (high), iPadOS (high)
Findings: HIGH=1, MEDIUM=0, LOW=1, INFO=0

- HIGH `permissions-missing-nscamerausagedescription`: Potential protected-resource use without NSCameraUsageDescription (medium)
  evidence: `Sources/CameraView.swift:4: _ = AVCaptureDevice.default(for: .video)`
```

Reproduce the complete output:

```bash
scripts/scan_apple_app_review_risks.py examples/demo-app --format compact --max-findings 4
```

The path in the excerpt is shortened; [`examples/demo-output.txt`](https://github.com/Kofiloski/app-store-review-risk/blob/main/examples/demo-output.txt) contains the normalized complete result used by the test suite.

The executable input reference is [action.yml](../action.yml). Use `app-store-review-risk --help` for all CLI options. Read [review scope and limitations](review-scope.md) before treating a finding as a policy conclusion.
