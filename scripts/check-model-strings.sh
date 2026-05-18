#!/usr/bin/env bash
# scripts/check-model-strings.sh — lint for hardcoded model identifiers.
#
# Hardcoded model strings (e.g. `claude-opus-4-7`, `gpt-4o-mini`)
# accumulate across the codebase when operators update models. When a
# new model ships, finding every place that needs updating is
# grep-driven. This script fails CI on any model-string hit outside
# the allowlist — the legitimate sites where these strings DO live
# (test fixtures, advisor translators, wizard-default sources, and
# operator-facing docs / config examples).
#
# Closes #155.
#
# Exit codes:
#   0 — clean (no hits, or every hit is allowlisted)
#   1 — hits outside the allowlist (CI fails)
#   2 — usage / harness error
#
# Usage:
#   scripts/check-model-strings.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Patterns the lint considers a model identifier.
PATTERNS=(
    'claude-[a-z0-9.-]+'
    'gpt-[a-z0-9.-]+'
)

# Paths to scan — restrict to source so the lint stays fast and
# targeted. Docs / config example files are NOT in the scan set;
# they're documented to carry model strings as examples and live
# under their own change-control.
SCAN_PATHS=(
    cmd
    internal
)

# Files where a hardcoded model string is legitimate:
#   - `*_test.go` — test fixtures.
#   - `internal/advisor/*translator*.go` — the translator layer
#     that names provider-specific defaults.
#   - `internal/advisor/anthropic_translator.go` — the
#     `AnthropicDefaultModel` constant home.
#   - `internal/advisor/aoai_endpoint.go` — godoc examples for the
#     AOAI endpoint parser.
#   - `cmd/trollbridge/init*.go` — wizard-default sources; these
#     are the operator-facing "update here when a new model ships"
#     locations, by design.
#   - `internal/setupplan/plan.go` — agent-facing plan template
#     default; same role as the wizard defaults.
is_allowlisted() {
    case "$1" in
        *_test.go)                                  return 0 ;;
        internal/advisor/*translator*.go)           return 0 ;;
        internal/advisor/aoai_endpoint.go)          return 0 ;;
        internal/advisor/aoai_responses_translator.go) return 0 ;;
        cmd/trollbridge/init*.go)                   return 0 ;;
        internal/setupplan/plan.go)                 return 0 ;;
        */testdata/*)                               return 0 ;;
        */fixtures/*)                               return 0 ;;
    esac
    return 1
}

cd "$REPO_ROOT"

hits=0
for pattern in "${PATTERNS[@]}"; do
    while IFS= read -r line; do
        path="${line%%:*}"
        if is_allowlisted "$path"; then
            continue
        fi
        echo "$line"
        hits=$((hits + 1))
    done < <(grep -nE -I -r "$pattern" "${SCAN_PATHS[@]}" 2>/dev/null || true)
done

if [[ $hits -gt 0 ]]; then
    echo "" >&2
    echo "scripts/check-model-strings.sh: $hits hardcoded model string(s) outside the allowlist." >&2
    echo "fix: move the identifier to a named constant in internal/advisor/, or move the surrounding file to the allowlist in this script if it is a wizard-default / plan-template / translator site." >&2
    exit 1
fi

echo "scripts/check-model-strings.sh: clean — no hardcoded model strings outside the allowlist." >&2
exit 0
