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
        self.assertIn("actions/setup-python@v5", metadata)
        self.assertIn("scripts/run-action.sh", metadata)
        self.assertIn("branding:", metadata)
        self.assertIn("uses: ./", ci_workflow)

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
        self.assertIn("app-store-review-risk.git@v0.3.0", skill)
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
        self.assertIn("needs: build", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("environment:\n      name: pypi", workflow)
        self.assertRegex(
            workflow,
            r"pypa/gh-action-pypi-publish@[0-9a-f]{40} # release/v1",
        )
        self.assertNotIn("secrets.", workflow)


if __name__ == "__main__":
    unittest.main()
