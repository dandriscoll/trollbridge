#!/usr/bin/env bash
# scripts/release.sh — cut a drawbridge release.
#
# Cross-builds the four realistic *nix target/arch combinations,
# tarballs each with LICENSE and README, emits a SHA256SUMS file,
# and uploads the artifacts to a GitHub release via the gh CLI.
#
# Usage:
#   scripts/release.sh <tag> [--dry-run] [--force] [--help]
#
# Examples:
#   scripts/release.sh v0.1.0 --dry-run    # build artifacts only
#   scripts/release.sh v0.1.0              # build + publish
#   scripts/release.sh v0.1.0 --force      # overwrite existing release
#
# Preflight: refuses to run unless
#   - the supplied tag exists locally,
#   - HEAD is exactly at that tag's commit,
#   - the working tree is clean,
#   - `gh auth status` succeeds (skipped under --dry-run),
#   - no release for the tag exists yet (override with --force).
#
# Tooling required (operator-installed):
#   bash, git, go (>= 1.26), tar, sha256sum or shasum, gh.
#
# Recovery from a partial publish: the artifacts in dist/ persist;
# `gh release upload <tag> dist/*` uploads what didn't make it.
# To delete a published release: `gh release delete <tag>` (and
# `git push --delete origin <tag>` if you also want to drop the tag).

set -euo pipefail

# ---------- argument parsing ----------

TAG=""
DRY_RUN=0
FORCE=0

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -euo/d'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --force)   FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)        echo "release failed: unknown flag '$1'; fix: see --help" >&2; exit 2 ;;
        *)
            if [[ -n "$TAG" ]]; then
                echo "release failed: only one tag accepted (got '$TAG' and '$1'); fix: see --help" >&2
                exit 2
            fi
            TAG="$1"; shift ;;
    esac
done

if [[ -z "$TAG" ]]; then
    usage; exit 1
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

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "release failed: not inside a git repository; fix: cd into the drawbridge checkout" >&2
    exit 2
fi
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist"

# ---------- preflight ----------

preflight() {
    # Tag exists.
    if ! git rev-parse --verify "${TAG}^{commit}" >/dev/null 2>&1; then
        echo "release failed: tag '$TAG' does not exist; fix: create it with 'git tag $TAG' first" >&2
        exit 1
    fi
    # HEAD is at tag.
    local head_sha tag_sha
    head_sha="$(git rev-parse HEAD)"
    tag_sha="$(git rev-parse "${TAG}^{commit}")"
    if [[ "$head_sha" != "$tag_sha" ]]; then
        echo "release failed: HEAD is not at $TAG ($head_sha vs $tag_sha); fix: 'git checkout $TAG' before releasing" >&2
        exit 1
    fi
    # Working tree clean. Tracked (unstaged + staged) AND untracked.
    if ! git diff --quiet HEAD -- || ! git diff --cached --quiet; then
        echo "release failed: working tree has uncommitted changes; fix: commit or stash before releasing" >&2
        exit 1
    fi
    if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
        echo "release failed: working tree has untracked files; fix: 'git status' to inspect, then commit, gitignore, or remove them before releasing" >&2
        exit 1
    fi
    # Embedded version sanity: 'git describe' at this commit must equal the tag.
    local described
    described="$(git describe --tags --always --dirty 2>/dev/null || echo "")"
    if [[ "$described" != "$TAG" ]]; then
        echo "release failed: 'git describe' returned '$described' but expected '$TAG'; fix: ensure the tag points at HEAD and there are no local edits" >&2
        exit 1
    fi
    # gh auth and existing-release check (skipped on dry-run).
    if [[ $DRY_RUN -eq 0 ]]; then
        if ! gh auth status >/dev/null 2>&1; then
            echo "release failed: gh CLI is not authenticated; fix: run 'gh auth login' first" >&2
            exit 1
        fi
        if gh release view "$TAG" >/dev/null 2>&1; then
            if [[ $FORCE -eq 0 ]]; then
                echo "release failed: a release for '$TAG' already exists; fix: 'gh release delete $TAG' or pass --force to overwrite" >&2
                exit 1
            fi
        fi
    fi
}

# ---------- build matrix ----------

# Same flags as Makefile build target so the released binary is
# byte-identical to a local 'make build' at the same commit on the
# same toolchain.
LDFLAGS="-s -w -X github.com/dandriscoll/drawbridge/internal/server.Version=${TAG}"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

build_matrix() {
    rm -rf "$DIST"
    mkdir -p "$DIST"
    local target os arch stage tarname
    for target in "${TARGETS[@]}"; do
        os="${target%/*}"
        arch="${target#*/}"
        stage="$(mktemp -d)"
        local dirname="drawbridge_${TAG}_${os}_${arch}"
        local stagedir="$stage/$dirname"
        mkdir -p "$stagedir"
        echo "build: $dirname" >&2
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -trimpath -ldflags="$LDFLAGS" \
            -o "$stagedir/drawbridge" ./cmd/drawbridge
        cp LICENSE README.md "$stagedir/"
        tarname="${dirname}.tar.gz"
        tar -czf "$DIST/$tarname" -C "$stage" "$dirname"
        rm -rf "$stage"
    done
    # SHA256SUMS — write inside dist/ so paths in the file are
    # filename-only (operators run `sha256sum -c SHA256SUMS` from
    # inside the directory).
    (cd "$DIST" && $SHA256_CMD drawbridge_*.tar.gz > SHA256SUMS)
}

# ---------- publish ----------

publish() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "dry-run: skipping gh release create" >&2
        echo "artifacts in $DIST:" >&2
        ls -l "$DIST" >&2
        return 0
    fi
    local create_args=( "$TAG" --generate-notes )
    if [[ $FORCE -eq 1 ]]; then
        # Delete the existing release (and its assets) before re-creating.
        gh release delete "$TAG" --yes >/dev/null 2>&1 || true
    fi
    echo "publish: creating release $TAG" >&2
    gh release create "${create_args[@]}" "$DIST"/drawbridge_*.tar.gz "$DIST/SHA256SUMS"
    echo "release: $(gh release view "$TAG" --json url -q .url)" >&2
}

# ---------- main ----------

preflight
build_matrix
publish
