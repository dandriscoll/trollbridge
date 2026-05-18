#!/usr/bin/env bash
# scripts/precommit-check.sh — guard against accidental large-file
# additions.
#
# The repo's .gitignore covers known build artifact directories
# (bin/, dist/) but a developer can still `git add` a stray binary
# that lives outside an ignored path. .gitignore is reactive; this
# script is a proactive pre-commit check that refuses to add any
# file above LIMIT_BYTES (default 5 MB) to the index without an
# explicit override.
#
# Closes #154.
#
# Exit codes:
#   0 — all staged paths are under the limit (or override was set)
#   1 — at least one staged file is over the limit
#   2 — usage / harness error
#
# Usage:
#   scripts/precommit-check.sh                 # gate the index
#   TROLLBRIDGE_LARGE_FILE_OK=1 scripts/precommit-check.sh
#                                              # override (CI checkout, intentional binary)
#
# Wire as a pre-commit hook:
#   ln -s ../../scripts/precommit-check.sh .git/hooks/pre-commit
set -euo pipefail

LIMIT_BYTES="${TROLLBRIDGE_LARGE_FILE_LIMIT:-5242880}"  # 5 MiB

if [[ "${TROLLBRIDGE_LARGE_FILE_OK:-0}" -eq 1 ]]; then
    echo "scripts/precommit-check.sh: TROLLBRIDGE_LARGE_FILE_OK=1 — skipping large-file check" >&2
    exit 0
fi

over_limit=()
# git diff --cached --name-only -z gives us all staged paths,
# safely separated for paths containing spaces / newlines.
while IFS= read -r -d '' path; do
    # Deleted files have no on-disk size; skip.
    if [[ ! -f "$path" ]]; then
        continue
    fi
    size="$(stat -c%s "$path" 2>/dev/null || stat -f%z "$path" 2>/dev/null || echo 0)"
    if [[ "$size" -gt "$LIMIT_BYTES" ]]; then
        over_limit+=("$path:$size")
    fi
done < <(git diff --cached --name-only -z)

if [[ ${#over_limit[@]} -eq 0 ]]; then
    exit 0
fi

echo "scripts/precommit-check.sh: refusing — ${#over_limit[@]} staged file(s) over ${LIMIT_BYTES} bytes:" >&2
for entry in "${over_limit[@]}"; do
    echo "  $entry" >&2
done
echo "" >&2
echo "fix: unstage the file(s) (`git reset HEAD <path>`), OR set" >&2
echo "TROLLBRIDGE_LARGE_FILE_OK=1 in the env to override for this commit (legitimate large additions: tagged binary artifacts, vendored test fixtures)." >&2
exit 1
