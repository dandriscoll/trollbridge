#!/usr/bin/env bash
# scripts/release-test.sh — preflight tests for scripts/release.sh.
#
# Sets up isolated temp clones to exercise preflight branches that
# require mutating git state. Currently covers:
#   - branch-behind-origin guard (issue #3)
#
# Designed to be extended: each scenario is a separate function;
# main() runs all of them and prints PASS/FAIL per assertion.
#
# Usage:
#   scripts/release-test.sh           # run all scenarios
#
# Exit code: 0 if all PASS, 1 if any FAIL.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_SH="${SCRIPT_DIR}/release.sh"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ ! -x "$RELEASE_SH" ]]; then
    echo "FAIL: $RELEASE_SH is not executable or does not exist" >&2
    exit 1
fi

# Track every temp dir so cleanup happens even on early exit.
TMPS=()
cleanup() {
    local d
    for d in "${TMPS[@]:-}"; do
        [[ -n "$d" && -d "$d" ]] && rm -rf "$d"
    done
}
trap cleanup EXIT

mktmp() {
    local d
    d="$(mktemp -d)"
    TMPS+=("$d")
    echo "$d"
}

PASSES=0
FAILS=0

pass() {
    echo "PASS: $1"
    PASSES=$((PASSES + 1))
}

fail() {
    echo "FAIL: $1" >&2
    if [[ -n "${2:-}" ]]; then
        echo "----- captured output -----" >&2
        echo "$2" >&2
        echo "---------------------------" >&2
    fi
    FAILS=$((FAILS + 1))
}

# ---------- scenarios ----------

test_branch_behind_origin_refuses() {
    local origin local_clone out exit_code
    origin="$(mktmp)"
    local_clone="$(mktmp)"

    # Clone the real repo into a "fake origin", then clone that into
    # the local. The local's `origin` remote then points at our fake.
    git -C "$origin" init --quiet --bare
    git -C "$REPO_ROOT" push --quiet "$origin" main
    git clone --quiet "$origin" "$local_clone"
    cp "$RELEASE_SH" "$local_clone/scripts/release.sh"
    git -C "$local_clone" -c user.email=t@t -c user.name=t commit -q --allow-empty \
        -am "test setup" 2>/dev/null || true

    # Push a NEW commit to origin so local is one behind.
    local origin_work
    origin_work="$(mktmp)"
    git clone --quiet "$origin" "$origin_work"
    git -C "$origin_work" -c user.email=t@t -c user.name=t \
        commit -q --allow-empty -m "ahead commit on origin"
    git -C "$origin_work" push --quiet origin main

    # Run release.sh WITHOUT --dry-run (the branch-uptodate check
    # is intentionally skipped under --dry-run since dry-run doesn't
    # push). The branch-uptodate check fires BEFORE the gh-auth
    # check in the preflight order, so an unconfigured gh CLI in
    # the test environment is harmless — the script refuses on
    # branch-behind first and never reaches gh.
    set +e
    out="$(cd "$local_clone" && "$RELEASE_SH" --bump minor --yes 2>&1)"
    exit_code=$?
    set -e

    if [[ $exit_code -eq 0 ]]; then
        fail "branch-behind-origin guard did not refuse (exit 0)" "$out"
        return
    fi
    if ! echo "$out" | grep -q "behind origin/main"; then
        fail "branch-behind-origin error did not mention 'behind origin/main'" "$out"
        return
    fi
    pass "branch-behind-origin guard refuses with the expected message"
}

# ---------- main ----------

test_branch_behind_origin_refuses

echo "---"
echo "results: ${PASSES} passed, ${FAILS} failed"
[[ $FAILS -eq 0 ]] && exit 0 || exit 1
