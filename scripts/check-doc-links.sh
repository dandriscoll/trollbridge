#!/usr/bin/env bash
# scripts/check-doc-links.sh — link / anchor checker for *.md files.
#
# Catches the doc-drift class where a markdown link points at a file
# that no longer exists. Validates local relative file links; does
# NOT chase external HTTP(S) URLs (those add network flakiness in
# CI and would belong in a separate lane).
#
# Closes #151.
#
# Exit codes:
#   0 — every local link resolves
#   1 — one or more dead links
#   2 — usage / harness error
#
# Usage:
#   scripts/check-doc-links.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Find every markdown file under tracked source; exclude .git,
# vendor, node_modules, build artifacts, and any .devbox tree (host
# devshell pulled in by some workflows but not under repo control).
mapfile -t md_files < <(find . \
    \( -path ./.git -o -path ./vendor -o -path ./node_modules -o -path ./bin -o -path ./dist -o -path './.devbox*' \) -prune -o \
    -type f -name '*.md' -print 2>/dev/null | sed -e 's|^\./||')

dead=0

# Python helper does the markdown link extraction and existence
# check. Keeps the regex in one place and the per-file logic
# legible. python3 is on every modern CI runner and on macOS by
# default.
python3 - "${md_files[@]}" <<'PY'
import os
import re
import sys

# Match markdown inline links [text](target) but skip image syntax
# (image links are valid even when "broken" in our render context).
LINK = re.compile(r'(?<!\!)\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)')

dead_total = 0
for path in sys.argv[1:]:
    base = os.path.dirname(path)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                for m in LINK.finditer(line):
                    target = m.group(1)
                    # Skip external links and bare anchors.
                    if target.startswith(('http://', 'https://', 'mailto:', '#')):
                        continue
                    # Strip fragments — we only validate file existence.
                    target_path = target.split('#', 1)[0]
                    if target_path == '':
                        continue
                    # Resolve relative to the source file.
                    resolved = os.path.normpath(os.path.join(base, target_path))
                    if not os.path.exists(resolved):
                        print(f"{path}:{lineno}: dead link → {target_path} (resolved {resolved})")
                        dead_total += 1
    except (IOError, UnicodeDecodeError) as e:
        print(f"{path}: read error: {e}", file=sys.stderr)
        sys.exit(2)

sys.exit(1 if dead_total > 0 else 0)
PY
rc=$?

if [[ $rc -eq 0 ]]; then
    echo "scripts/check-doc-links.sh: clean — every local markdown link resolves." >&2
elif [[ $rc -eq 1 ]]; then
    echo "" >&2
    echo "scripts/check-doc-links.sh: one or more dead links above." >&2
    echo "fix: update the target path, or restore the missing file." >&2
fi

exit $rc
