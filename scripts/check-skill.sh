#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m compileall -q src scripts tests
python3 -m unittest tests/test_scanner.py
scripts/scan_apple_app_review_risks.py . --format compact --max-findings 20
if git grep -I -n '[[:blank:]]$' -- .; then
  echo "Trailing whitespace found in tracked files." >&2
  exit 1
fi
git diff --check
git diff --cached --check

echo "app-store-review-risk checks passed."
