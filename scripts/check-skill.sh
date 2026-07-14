#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m compileall -q src scripts tests
python3 -m unittest discover -s tests
echo "Running scanner against the intentionally incomplete demo fixture (expected HIGH=1)."
scripts/scan_apple_app_review_risks.py examples/demo-app --format compact --max-findings 20
if git grep -I -n '[[:blank:]]$' -- .; then
  echo "Trailing whitespace found in tracked files." >&2
  exit 1
fi
git diff --check
git diff --cached --check

echo "app-store-review-risk checks passed."
