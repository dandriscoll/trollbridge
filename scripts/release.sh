#!/usr/bin/env bash
# scripts/release.sh — bump version, tag, and cut a trollbridge release.
#
# Single-command release flow: reads the current version from the
# README, prompts for major/minor/patch, computes the new version,
# edits the version-bearing files, commits + annotated-tags,
# cross-builds the four realistic *nix target/arch combinations,
# pushes main + the new tag to origin, and uploads the artifacts to
# a GitHub release via the gh CLI.
#
# Usage:
#   scripts/release.sh [--bump <major|minor|patch>] [--prerelease <suffix>]
#                      [--yes] [--dry-run] [--force] [--help]
#
# Examples:
#   scripts/release.sh                                  # interactive: prompts for kind, then [y/N]
#   scripts/release.sh --bump minor                     # non-interactive kind, still prompts [y/N]
#   scripts/release.sh --bump minor --yes               # non-interactive end-to-end
#   scripts/release.sh --bump patch --yes               # patch release, e.g., v0.2.0 -> v0.2.1
#   scripts/release.sh --bump minor --prerelease rc.1   # pre-release, e.g., v0.1.0 -> v0.2.0-rc.1
#   scripts/release.sh --dry-run                        # apply bumps to working tree, build dist/, skip commit/tag/push/publish
#   scripts/release.sh --bump major --force             # overwrite an already-published release at the new tag
#
# Pre-release semantics (MVP — see issue #2 for limitations):
#   - --prerelease <suffix> appends "-<suffix>" to the bumped version.
#   - If the current version (parsed from README) already has a
#     "-<suffix>" segment, the bump axis applies to the version
#     BEFORE that suffix (so v0.2.0-rc.1 + --bump minor +
#     --prerelease rc.2 -> v0.3.0-rc.2).
#   - --prerelease REQUIRES --bump in the MVP. Iterating an rc on
#     the same target version, or finalizing an rc to its release,
#     is not yet supported; manually tag for those cases.
#
# Preflight (fail-closed before any destructive action):
#   - working tree clean (tracked AND untracked),
#   - on a branch up-to-date with origin/main (no behind-state),
#   - README contains a parseable `releases/download/vX.Y.Z/` URL,
#   - `gh auth status` succeeds (skipped under --dry-run),
#   - new tag does not already exist locally,
#   - no GitHub release for the new tag (override with --force).
#
# Tooling required (operator-installed):
#   bash, git, go (>= 1.26), tar, sed, sha256sum or shasum, gh.
#
# Recovery:
#   - Build failed AFTER bump commit + tag, BEFORE push:
#       git tag -d vNEW && git reset --hard HEAD~1
#   - Build failed AFTER push, BEFORE publish:
#       gh release create vNEW dist/*.tar.gz dist/SHA256SUMS  # finish the publish
#       OR: gh release upload vNEW dist/*  (if release already exists)
#   - Full unwind of a published release (DESTRUCTIVE; revert is preferred over force-push):
#       gh release delete vNEW
#       git push --delete origin vNEW
#       git tag -d vNEW
#       git revert <bump-sha> && git push origin main

set -euo pipefail

# ---------- argument parsing ----------

BUMP=""
PRERELEASE=""
YES=0
DRY_RUN=0
FORCE=0

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -euo/d'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bump)
            BUMP="${2:-}"
            if [[ -z "$BUMP" ]]; then
                echo "release failed: --bump requires an argument; fix: --bump <major|minor|patch>" >&2
                exit 2
            fi
            shift 2
            ;;
        --prerelease)
            PRERELEASE="${2:-}"
            if [[ -z "$PRERELEASE" ]]; then
                echo "release failed: --prerelease requires a non-empty suffix; fix: --prerelease rc.1 (or similar)" >&2
                exit 2
            fi
            shift 2
            ;;
        --yes)     YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --force)   FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "release failed: unexpected argument '$1'; fix: see --help" >&2
            exit 2
            ;;
    esac
done

# MVP: --prerelease requires --bump (iterate / finalize not yet
# supported; see issue #2).
if [[ -n "$PRERELEASE" && -z "$BUMP" ]]; then
    echo "release failed: --prerelease requires --bump in the MVP (issue #2 v2 will support iterate/finalize); fix: pass --bump <axis> alongside --prerelease, or manually tag for iterate/finalize" >&2
    exit 2
fi

# ---------- environment detection ----------

if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD="shasum -a 256"
else
    echo "release failed: neither sha256sum nor shasum is on PATH; fix: install GNU coreutils or BSD shasum" >&2
    exit 2
fi

# sed -i portability: GNU sed accepts `sed -i 'EXPR'`; BSD/macOS sed
# requires `sed -i '' 'EXPR'`. Detect once.
sed_inplace() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "release failed: not inside a git repository; fix: cd into the trollbridge checkout" >&2
    exit 2
fi
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist"
README="$REPO_ROOT/README.md"
SERVER_GO="$REPO_ROOT/internal/server/server.go"

# ---------- discover current version ----------

# Anchor: the README's release-asset URL fragment, e.g.,
#   releases/download/v0.1.0/trollbridge_v0.1.0_linux_amd64.tar.gz
# Or with a pre-release suffix:
#   releases/download/v0.2.0-rc.1/trollbridge_v0.2.0-rc.1_linux_amd64.tar.gz
# Stable across releases because release.sh always tarball-names the
# same way.
discover_current_version() {
    local v
    v="$(grep -oE 'releases/download/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?/' "$README" | head -1 \
        | sed -E 's|releases/download/v([0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?)/|\1|')"
    if [[ -z "$v" ]]; then
        echo "discover failed: cannot find a 'releases/download/vX.Y.Z[-suffix]/' URL in README; fix: ensure README has the install snippet from job 040" >&2
        exit 1
    fi
    echo "$v"
}

# ---------- prompt + compute new version ----------

prompt_bump_kind() {
    local answer
    if [[ -n "$BUMP" ]]; then
        answer="$BUMP"
    else
        # Read full word; one shot, no loop. Operator who fat-fingers
        # gets a clear error and re-runs.
        read -r -p "bump kind [major|minor|patch]: " answer
    fi
    # Case-fold so 'Major', 'MINOR', etc. all work.
    echo "$answer" | tr '[:upper:]' '[:lower:]'
}

# Strip an optional "-<suffix>" segment from a version string.
# "0.2.0-rc.1" -> "0.2.0"; "0.2.0" -> "0.2.0".
strip_prerelease() {
    echo "${1%%-*}"
}

compute_new_version() {
    # Accepts a current version with OR without a pre-release suffix
    # (e.g., "0.2.0" or "0.2.0-rc.1"). The bump axis applies to the
    # SemVer-numeric portion only; any suffix on the current version
    # is dropped before the math, and the caller in main re-appends
    # the new --prerelease suffix if one was supplied.
    local current="$1" kind="$2"
    local numeric major minor patch
    numeric="$(strip_prerelease "$current")"
    IFS=. read -r major minor patch <<< "$numeric"
    case "$kind" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
        *)
            echo "bump failed: invalid kind '$kind'; fix: use 'major', 'minor', or 'patch'" >&2
            exit 1
            ;;
    esac
}

confirm() {
    local prompt="$1" answer
    if [[ $YES -eq 1 ]]; then
        return 0
    fi
    read -r -p "$prompt [y/N]: " answer
    case "$(echo "$answer" | tr '[:upper:]' '[:lower:]')" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- preflight ----------

preflight_clean_tree() {
    if ! git diff --quiet HEAD -- || ! git diff --cached --quiet; then
        echo "release failed: working tree has uncommitted changes; fix: commit or stash before releasing" >&2
        exit 1
    fi
    if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
        echo "release failed: working tree has untracked files; fix: 'git status' to inspect, then commit, gitignore, or remove them before releasing" >&2
        exit 1
    fi
}

preflight_branch_uptodate() {
    # Skip in dry-run since we don't push.
    if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
    if ! git fetch --quiet origin main 2>/dev/null; then
        echo "release failed: 'git fetch origin main' failed; fix: check network/auth to origin" >&2
        exit 1
    fi
    local behind
    behind="$(git rev-list --count HEAD..origin/main)"
    if [[ "$behind" -gt 0 ]]; then
        echo "release failed: branch is $behind commits behind origin/main; fix: 'git pull --ff-only origin main' first" >&2
        exit 1
    fi
}

preflight_no_tag_yet() {
    local tag="$1"
    if git rev-parse --verify "${tag}^{commit}" >/dev/null 2>&1; then
        echo "release failed: tag '$tag' already exists locally; fix: 'git tag -d $tag' if it's a stale dry-run remnant, or pick a different bump kind" >&2
        exit 1
    fi
}

preflight_gh_release() {
    local tag="$1"
    if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
    if ! gh auth status >/dev/null 2>&1; then
        echo "release failed: gh CLI is not authenticated; fix: run 'gh auth login' first" >&2
        exit 1
    fi
    if gh release view "$tag" >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        echo "release failed: a GitHub release for '$tag' already exists; fix: 'gh release delete $tag' or pass --force to overwrite" >&2
        exit 1
    fi
}

# ---------- bump version-bearing files ----------

apply_bumps() {
    local old="$1" new="$2"
    # README: only the URL fragments. Anchored on the surrounding
    # `releases/download/` path and the `trollbridge_v` filename
    # prefix to avoid clobbering unrelated text.
    sed_inplace -E \
        -e "s|releases/download/v${old}/|releases/download/v${new}/|g" \
        -e "s|trollbridge_v${old}_|trollbridge_v${new}_|g" \
        -e "s|trollbridge_v${old}_linux_amd64/trollbridge|trollbridge_v${new}_linux_amd64/trollbridge|g" \
        "$README"
    # server.go: only the literal `var Version = "<old>-dev"` line.
    sed_inplace -E "s|^var Version = \"${old}-dev\"|var Version = \"${new}-dev\"|" "$SERVER_GO"

    # Verify both files actually changed; if either didn't, the
    # anchor pattern is wrong (probably already-bumped or hand-
    # edited). Bail loudly.
    # Each of the three README anchors must now reflect v${new}. A
    # missed anchor (e.g., README hand-edited away from the canonical
    # form) leaves a partially-bumped install snippet — the URL might
    # be right while the install-line filename is stale. Catch all
    # three positively, not by checking that v${old} is absent (which
    # the hand-edit case would defeat vacuously).
    local missing=()
    grep -q "releases/download/v${new}/" "$README" || missing+=("URL fragment 'releases/download/v${new}/'")
    grep -q "trollbridge_v${new}_" "$README" || missing+=("tarball-name fragment 'trollbridge_v${new}_'")
    grep -q "trollbridge_v${new}_linux_amd64/trollbridge" "$README" || missing+=("install-line fragment 'trollbridge_v${new}_linux_amd64/trollbridge'")
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "bump failed: README is missing the following after sed:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        echo "fix: ensure README's install snippet matches the canonical form (vX.Y.Z URL + tarball-name + install line all referencing the same version)" >&2
        exit 1
    fi
    if ! grep -q "var Version = \"${new}-dev\"" "$SERVER_GO"; then
        echo "bump failed: server.go did not pick up ${new}-dev after sed; fix: inspect var Version in $SERVER_GO" >&2
        exit 1
    fi
}

# ---------- commit + tag ----------

commit_and_tag() {
    local new="$1"
    git add "$README" "$SERVER_GO"
    git commit -m "release: bump version to v${new}" \
               -m "Updates the README install-snippet URL and the internal/server/server.go" \
               -m "var Version fallback. The fallback is shown only when trollbridge is" \
               -m "built without the release script's -ldflags injection (e.g. 'go run')." \
               >/dev/null
    git tag -a "v${new}" -m "release v${new}"
    echo "commit: $(git rev-parse --short HEAD)" >&2
    echo "tag: v${new}" >&2
}

# ---------- build matrix ----------

LDFLAGS_FOR() {
    echo "-s -w -X github.com/dandriscoll/trollbridge/internal/server.Version=v$1"
}

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

build_matrix() {
    local new="$1"
    rm -rf "$DIST"
    mkdir -p "$DIST"
    local ldflags target os arch stage tarname dirname binary
    ldflags="$(LDFLAGS_FOR "$new")"
    for target in "${TARGETS[@]}"; do
        os="${target%/*}"
        arch="${target#*/}"
        stage="$(mktemp -d)"
        dirname="trollbridge_v${new}_${os}_${arch}"
        binary="trollbridge"
        [[ "$os" == "windows" ]] && binary="trollbridge.exe"
        mkdir -p "$stage/$dirname"
        echo "build: $dirname" >&2
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -trimpath -ldflags="$ldflags" \
            -o "$stage/$dirname/$binary" ./cmd/trollbridge
        cp LICENSE README.md "$stage/$dirname/"
        tarname="${dirname}.tar.gz"
        tar -czf "$DIST/$tarname" -C "$stage" "$dirname"
        rm -rf "$stage"
    done
    (cd "$DIST" && $SHA256_CMD trollbridge_*.tar.gz > SHA256SUMS)
}

# ---------- push + publish ----------

push_and_publish() {
    local new="$1"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "dry-run: skipping commit/tag/push/publish" >&2
        echo "dry-run: artifacts in $DIST:" >&2
        ls -l "$DIST" >&2
        echo "dry-run: working tree changes pending. Revert with: git checkout README.md internal/server/server.go" >&2
        return 0
    fi
    echo "push: origin main" >&2
    git push origin main
    echo "push: origin v${new}" >&2
    git push origin "v${new}"
    if [[ $FORCE -eq 1 ]] && gh release view "v${new}" >/dev/null 2>&1; then
        echo "force: deleting existing release v${new}" >&2
        gh release delete "v${new}" --yes >/dev/null 2>&1 || true
    fi
    echo "publish: creating release v${new}" >&2
    gh release create "v${new}" --generate-notes "$DIST"/trollbridge_*.tar.gz "$DIST/SHA256SUMS"
    echo "release: $(gh release view "v${new}" --json url -q .url)" >&2
}

# ---------- main ----------

CURRENT="$(discover_current_version)"
echo "discover: current version v${CURRENT}" >&2

KIND="$(prompt_bump_kind)"
NEW="$(compute_new_version "$CURRENT" "$KIND")"
if [[ -n "$PRERELEASE" ]]; then
    NEW="${NEW}-${PRERELEASE}"
fi
echo "bump: v${CURRENT} → v${NEW}" >&2

if ! confirm "proceed with bump to v${NEW}?"; then
    echo "release: aborted by user" >&2
    exit 0
fi

preflight_clean_tree
preflight_branch_uptodate
preflight_no_tag_yet "v${NEW}"
preflight_gh_release "v${NEW}"

apply_bumps "$CURRENT" "$NEW"
echo "apply: README updated" >&2
echo "apply: server.go updated" >&2

if [[ $DRY_RUN -eq 0 ]]; then
    commit_and_tag "$NEW"
fi

build_matrix "$NEW"

push_and_publish "$NEW"
