#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def package_version() -> str:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    runtime = (ROOT / "src" / "app_store_review_risk" / "__init__.py").read_text(encoding="utf-8")
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    project_match = re.search(r'^version = "([^"]+)"', project, re.MULTILINE)
    runtime_match = re.search(r'^__version__ = "([^"]+)"', runtime, re.MULTILINE)
    citation_match = re.search(r"^version: ([^\n]+)", citation, re.MULTILINE)
    if project_match is None:
        raise ValueError("pyproject.toml does not contain a project version")
    if runtime_match is None:
        raise ValueError("package __init__.py does not contain a runtime version")
    if citation_match is None:
        raise ValueError("CITATION.cff does not contain a software version")

    versions = {
        "pyproject.toml": project_match.group(1),
        "package __init__.py": runtime_match.group(1),
        "CITATION.cff": citation_match.group(1),
    }
    if len(set(versions.values())) != 1:
        details = ", ".join(f"{source}={version}" for source, version in versions.items())
        raise ValueError(f"Release version metadata does not match: {details}")
    return project_match.group(1)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check-release-version.py <release-tag>", file=sys.stderr)
        return 2

    actual_tag = argv[0]
    expected_tag = f"v{package_version()}"
    if actual_tag != expected_tag:
        print(f"Release tag {actual_tag!r} does not match package version tag {expected_tag!r}.", file=sys.stderr)
        return 1

    print(f"Release tag {actual_tag} matches the package version.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
