#!/usr/bin/env bash

set -euo pipefail

args=(
  "${INPUT_PATH:-.}"
  --format "${INPUT_FORMAT:-compact}"
  --max-findings "${INPUT_MAX_FINDINGS:-12}"
  --fail-on "${INPUT_FAIL_ON:-high}"
)

append_if_set() {
  local flag="$1"
  local value="$2"
  if [[ -n "$value" ]]; then
    args+=("$flag" "$value")
  fi
}

append_if_set --submitted-target "${INPUT_SUBMITTED_TARGET:-}"
append_if_set --diff "${INPUT_DIFF:-}"
append_if_set --base-ref "${INPUT_BASE_REF:-}"
append_if_set --head-ref "${INPUT_HEAD_REF:-}"
append_if_set --project "${INPUT_PROJECT:-}"
append_if_set --workspace "${INPUT_WORKSPACE:-}"
append_if_set --scheme "${INPUT_SCHEME:-}"

case "${INPUT_XCODEBUILD:-false}" in
  true)
    args+=(--xcodebuild)
    ;;
  false)
    ;;
  *)
    echo "xcodebuild input must be 'true' or 'false'." >&2
    exit 2
    ;;
esac

exec app-store-review-risk "${args[@]}"
