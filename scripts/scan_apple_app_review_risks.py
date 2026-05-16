#!/usr/bin/env python3
"""Compatibility wrapper for the packaged app-store-review-risk CLI."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))

from app_store_review_risk.cli import *  # noqa: F401,F403,E402
from app_store_review_risk.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
