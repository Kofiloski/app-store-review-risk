from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTION_RUNNER = ROOT / "scripts" / "run-action.sh"
RELEASE_VERSION_CHECK = ROOT / "scripts" / "check-release-version.py"
SCANNER = ROOT / "scripts" / "scan_apple_app_review_risks.py"
SKILL_ROOT = ROOT / "skills" / "app-store-review-risk"
MINIMUM_NODE24_ACTION_MAJORS = {
    "actions/checkout": 5,
    "actions/setup-python": 6,
    "actions/upload-artifact": 6,
    "actions/download-artifact": 7,
}
ACTION_REFERENCE = re.compile(
    r"^[ \t]*(?:-[ \t]*)?(?:uses|['\"]uses['\"]):[ \t]*['\"]?"
    r"(?P<action>actions/[a-z0-9_-]+)@(?P<ref>[^'\"\s#]+)",
    re.IGNORECASE | re.MULTILINE,
)
ACTION_MAJOR_REF = re.compile(r"v(?P<major>\d+)(?:\.\d+){0,2}\Z", re.IGNORECASE)
BLOCK_SCALAR_START = re.compile(
    r"^[ ]*(?:-[ ]*)?(?:[A-Za-z0-9_-]+|['\"][^'\"]+['\"]):"
    r"[ ]*[|>][0-9+-]*[ ]*(?:#.*)?$"
)


def action_references(text: str):
    block_parent_indent: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if block_parent_indent is not None:
            if not stripped or indent > block_parent_indent:
                continue
            block_parent_indent = None

        if BLOCK_SCALAR_START.match(line):
            block_parent_indent = indent
            continue

        match = ACTION_REFERENCE.match(line)
        if match:
            yield match


def reviewed_node24_major(action: str, ref: str) -> int:
    minimum = MINIMUM_NODE24_ACTION_MAJORS.get(action)
    if minimum is None:
        raise ValueError(f"{action} has no reviewed Node 24 minimum")
    version = ACTION_MAJOR_REF.fullmatch(ref)
    if version is None:
        raise ValueError(f"{action}@{ref} requires explicit Node 24 review")
    major = int(version.group("major"))
    if major < minimum:
        raise ValueError(
            f"{action}@{ref} requires at least v{minimum} for Node 24"
        )
    return major


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class DistributionTests(unittest.TestCase):
    def run_action(self, **overrides: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            capture = temp_root / "arguments.txt"
            executable = temp_root / "app-store-review-risk"
            write_executable(
                executable,
                "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$CAPTURE_PATH\"\n",
            )
            env = {
                **os.environ,
                "PATH": f"{temp_root}{os.pathsep}{os.environ['PATH']}",
                "CAPTURE_PATH": str(capture),
                **overrides,
            }
            result = subprocess.run(
                ["bash", str(ACTION_RUNNER)],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            arguments = capture.read_text(encoding="utf-8").splitlines() if capture.exists() else []
            return result, arguments

    def test_action_runner_preserves_inputs_as_arguments(self):
        result, arguments = self.run_action(
            INPUT_PATH="App Project",
            INPUT_FORMAT="compact-json",
            INPUT_MAX_FINDINGS="7",
            INPUT_FAIL_ON="medium",
            INPUT_SUBMITTED_TARGET="Customer App",
            INPUT_DIFF="base...head",
            INPUT_BASE_REF="v1.0.0",
            INPUT_HEAD_REF="v1.1.0",
            INPUT_PROJECT="App Project/App.xcodeproj",
            INPUT_WORKSPACE="App Project/App.xcworkspace",
            INPUT_SCHEME="Release Scheme",
            INPUT_XCODEBUILD="true",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            arguments,
            [
                "App Project",
                "--format",
                "compact-json",
                "--max-findings",
                "7",
                "--fail-on",
                "medium",
                "--submitted-target",
                "Customer App",
                "--diff",
                "base...head",
                "--base-ref",
                "v1.0.0",
                "--head-ref",
                "v1.1.0",
                "--project",
                "App Project/App.xcodeproj",
                "--workspace",
                "App Project/App.xcworkspace",
                "--scheme",
                "Release Scheme",
                "--xcodebuild",
            ],
        )

    def test_action_runner_defaults_are_safe_and_minimal(self):
        result, arguments = self.run_action()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            arguments,
            [".", "--format", "compact", "--max-findings", "12", "--fail-on", "high"],
        )

    def test_action_runner_rejects_invalid_boolean(self):
        result, arguments = self.run_action(INPUT_XCODEBUILD="yes")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(arguments, [])
        self.assertIn("must be 'true' or 'false'", result.stderr)

    def test_action_metadata_exposes_composite_marketplace_entrypoint(self):
        metadata = (ROOT / "action.yml").read_text(encoding="utf-8")
        ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

        self.assertIn('name: "App Store Review Risk"', metadata)
        self.assertIn('using: "composite"', metadata)
        self.assertIn("actions/setup-python@v6", metadata)
        self.assertIn("scripts/run-action.sh", metadata)
        self.assertIn("branding:", metadata)
        self.assertIn("uses: ./", ci_workflow)

    def test_workflows_do_not_use_node_20_action_majors(self):
        action_and_workflows = [
            ROOT / "action.yml",
            *(ROOT / ".github" / "workflows").glob("*.yml"),
            *(ROOT / ".github" / "workflows").glob("*.yaml"),
        ]
        content = "\n".join(path.read_text(encoding="utf-8") for path in action_and_workflows)

        checked_references = 0
        for match in action_references(content):
            action = match.group("action").lower()
            checked_references += 1
            reviewed_node24_major(action, match.group("ref"))

        self.assertGreater(checked_references, 0)
        self.assertIsNone(
            ACTION_REFERENCE.search("# migrated from uses: actions/setup-python@v5")
        )
        self.assertEqual(
            [
                match.group("ref")
                for match in action_references(
                    "run: |\n  uses: actions/setup-python@v5\n"
                    "- uses: actions/setup-python@v6\n"
                )
            ],
            ["v6"],
        )
        self.assertEqual(
            [
                match.group("ref")
                for match in action_references(
                    '- "uses": actions/setup-python@v5\n'
                )
            ],
            ["v5"],
        )
        with self.assertRaisesRegex(ValueError, "requires explicit Node 24 review"):
            reviewed_node24_major("actions/setup-python", "a" * 40)
        self.assertIn("actions/setup-python@v6", content)
        self.assertIn("actions/upload-artifact@v6", content)
        self.assertIn("actions/download-artifact@v7", content)

    def test_demo_output_matches_the_real_scanner(self):
        demo_root = ROOT / "examples" / "demo-app"
        result = subprocess.run(
            [str(SCANNER), str(demo_root), "--format", "compact", "--max-findings", "4"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        normalized = result.stdout.replace(
            f"Target: `{demo_root.resolve()}`",
            "Target: `examples/demo-app`",
        )
        expected = (ROOT / "examples" / "demo-output.txt").read_text(encoding="utf-8")
        self.assertEqual(normalized, expected)

    def test_skill_frontmatter_uses_only_name_and_description(self):
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", skill, re.DOTALL)
        self.assertIsNotNone(match)
        keys = [line.split(":", 1)[0] for line in match.group(1).splitlines() if ":" in line]
        self.assertEqual(keys, ["name", "description"])
        name = next(line.split(":", 1)[1].strip() for line in match.group(1).splitlines() if line.startswith("name:"))
        self.assertEqual(name, SKILL_ROOT.name)

    def test_root_skill_preserves_legacy_direct_clone_installations(self):
        root_skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("name: app-store-review-risk", root_skill)
        self.assertIn("skills/app-store-review-risk/SKILL.md", root_skill)
        self.assertTrue((ROOT / "agents" / "openai.yaml").is_file())

    def test_published_skill_uses_installed_or_release_pinned_scanner(self):
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("app-store-review-risk /path/to/app/repo", skill)
        self.assertIn(
            "uvx --from app-store-review-risk==0.3.1 app-store-review-risk",
            skill,
        )
        self.assertNotIn("scripts/scan_apple_app_review_risks.py", skill)
        self.assertTrue((SKILL_ROOT / "agents" / "openai.yaml").is_file())
        self.assertTrue((SKILL_ROOT / "references" / "apple-platform-risk-areas.md").is_file())

    def test_citation_version_matches_package_version(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        package_version = re.search(r'^version = "([^"]+)"', project, re.MULTILINE)
        citation_version = re.search(r"^version: ([^\n]+)", citation, re.MULTILINE)

        self.assertIsNotNone(package_version)
        self.assertIsNotNone(citation_version)
        self.assertEqual(citation_version.group(1), package_version.group(1))

    def test_cli_reports_package_version_without_a_scan_path(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package_version = re.search(r'^version = "([^"]+)"', project, re.MULTILINE)
        self.assertIsNotNone(package_version)

        result = subprocess.run(
            [str(SCANNER), "--version"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.stdout.strip(), package_version.group(1))

    def test_release_version_check_accepts_only_the_package_tag(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        package_version = re.search(r'^version = "([^"]+)"', project, re.MULTILINE)
        self.assertIsNotNone(package_version)
        accepted = subprocess.run(
            [str(RELEASE_VERSION_CHECK), f"v{package_version.group(1)}"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        rejected = subprocess.run(
            [str(RELEASE_VERSION_CHECK), "v9.9.9"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("does not match", rejected.stderr)

    def test_pypi_workflow_uses_separate_oidc_publish_job(self):
        workflow = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")

        self.assertIn("release:\n    types:\n      - published", workflow)
        self.assertIn("workflow_dispatch:\n    inputs:\n      release_tag:", workflow)
        self.assertIn(
            "group: pypi-${{ github.event.release.tag_name || inputs.release_tag }}",
            workflow,
        )
        self.assertIn("github.ref != 'refs/heads/main'", workflow)
        self.assertIn(
            "ref: refs/tags/${{ github.event.release.tag_name || inputs.release_tag }}",
            workflow,
        )
        self.assertIn("gh release view", workflow)
        self.assertIn("isDraft,tagName", workflow)
        self.assertIn('git show-ref --verify --quiet "refs/tags/${RELEASE_TAG}"', workflow)
        self.assertIn('git rev-list -n 1 "refs/tags/${RELEASE_TAG}"', workflow)
        self.assertIn('git rev-parse HEAD', workflow)
        self.assertIn('python scripts/check-release-version.py "${RELEASE_TAG}"', workflow)
        self.assertIn("app-store-review-risk --version", workflow)
        self.assertIn("needs: build", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("environment:\n      name: pypi", workflow)
        self.assertIn("skip-existing: true", workflow)
        self.assertIn("attestations: true", workflow)
        self.assertRegex(
            workflow,
            r"pypa/gh-action-pypi-publish@[0-9a-f]{40} # release/v1",
        )
        self.assertNotIn("secrets.", workflow)

    def test_tag_push_creates_the_github_release_without_personal_auth(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('tags:\n      - "v*.*.*"', workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn('python scripts/check-release-version.py "${RELEASE_TAG}"', workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('gh release create "${RELEASE_TAG}"', workflow)
        self.assertIn("gh workflow run publish-pypi.yml", workflow)
        self.assertIn('--field release_tag="${RELEASE_TAG}"', workflow)
        self.assertNotIn("secrets.", workflow)


if __name__ == "__main__":
    unittest.main()
