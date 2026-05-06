package hostlist

import (
	"sort"
	"strconv"
	"strings"
)

// Smart re-sorts the lines of a flat-list file with wildcard-aware
// ordering. The leading comment block (lines beginning with `#`
// before any non-comment line) is preserved at the top in its
// original order. Patterns and their inline comments are sorted
// together. Blank lines among patterns are dropped (the leading
// comment block keeps its blanks).
//
// Sort key for a pattern `host[:port][/path]`:
//   1. Reversed labels of host (case-insensitive). Wildcards
//      sort AFTER literal labels at the same depth, so
//      `*.github.com` falls right after the GitHub-related
//      patterns rather than at the top of the file.
//   2. Port (numeric; omitted = 0).
//   3. Path string (lexicographic; empty before non-empty).
//   4. Raw line text as a final tie-break for stability.
func Smart(lines []string) []string {
	// 1. Split off the leading comment block.
	var leading []string
	i := 0
	for i < len(lines) {
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "#") {
			leading = append(leading, lines[i])
			i++
			continue
		}
		break
	}

	// 2. Collect the rest. Skip blanks. Keep each pattern line as
	// authored (so inline comments survive).
	rest := lines[i:]
	type entry struct {
		raw          string
		key          sortKey
	}
	entries := make([]entry, 0, len(rest))
	for _, ln := range rest {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		// Lines that are JUST comments (no pattern) survive in
		// place with the next pattern they precede; for the first
		// pass keep this simple and drop them.
		if strings.HasPrefix(t, "#") {
			continue
		}
		entries = append(entries, entry{
			raw: ln,
			key: keyFor(t),
		})
	}

	sort.SliceStable(entries, func(a, b int) bool {
		return entries[a].key.less(entries[b].key, entries[a].raw, entries[b].raw)
	})

	out := make([]string, 0, len(leading)+len(entries))
	out = append(out, leading...)
	if len(leading) > 0 && len(entries) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
		out = append(out, "")
	}
	for _, e := range entries {
		out = append(out, e.raw)
	}
	return out
}

type sortKey struct {
	hostLabels []string // reversed
	hostFlags  []bool   // true at index where label is `*`
	port       int      // 0 if unspecified or wildcard
	pathStr    string
}

// keyFor parses a single line (not blank, not pure comment) into a
// sortKey. Strips the trailing inline comment for parsing only.
func keyFor(line string) sortKey {
	// Drop inline comment for key-extraction purposes.
	pat := line
	if i := strings.Index(pat, " #"); i >= 0 {
		pat = strings.TrimSpace(pat[:i])
	}

	// Split off path.
	hostport := pat
	pathStr := ""
	if i := strings.IndexByte(pat, '/'); i >= 0 {
		hostport = pat[:i]
		pathStr = pat[i:]
	}

	host := hostport
	port := 0
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		ps := hostport[i+1:]
		if ps == "" || ps == "*" {
			port = 0
		} else if n, err := strconv.Atoi(ps); err == nil {
			port = n
		}
	}

	host = strings.ToLower(strings.TrimSpace(host))

	// Reverse labels, marking wildcards.
	parts := strings.Split(host, ".")
	rev := make([]string, len(parts))
	flags := make([]bool, len(parts))
	for i := range parts {
		j := len(parts) - 1 - i
		rev[i] = parts[j]
		flags[i] = parts[j] == "*"
	}

	return sortKey{
		hostLabels: rev,
		hostFlags:  flags,
		port:       port,
		pathStr:    pathStr,
	}
}

// less compares sortKeys. Wildcards (`*`) sort AFTER literal
// labels at the same position. Shorter host (fewer labels) sorts
// before longer-with-the-same-prefix.
func (a sortKey) less(b sortKey, rawA, rawB string) bool {
	n := len(a.hostLabels)
	if len(b.hostLabels) < n {
		n = len(b.hostLabels)
	}
	for i := 0; i < n; i++ {
		ai, bi := a.hostLabels[i], b.hostLabels[i]
		af, bf := a.hostFlags[i], b.hostFlags[i]
		switch {
		case af && !bf:
			return false // wildcard sorts after literal at same depth
		case !af && bf:
			return true
		default:
			if ai != bi {
				return ai < bi
			}
		}
	}
	if len(a.hostLabels) != len(b.hostLabels) {
		return len(a.hostLabels) < len(b.hostLabels)
	}
	if a.port != b.port {
		return a.port < b.port
	}
	if a.pathStr != b.pathStr {
		return a.pathStr < b.pathStr
	}
	return rawA < rawB
}

// AppendUnique returns a new slice formed by adding `pattern` to
// `lines` if no existing line (after stripping inline comments and
// whitespace) equals it. The resulting slice is run through Smart.
func AppendUnique(lines []string, pattern string) ([]string, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return lines, false
	}
	for _, ln := range lines {
		if normalizePattern(ln) == strings.ToLower(pattern) {
			return lines, false
		}
	}
	return Smart(append(lines, pattern)), true
}

// RemoveMatching removes any line whose stripped pattern matches
// `pattern` (case-insensitive). Returns the new slice and whether
// anything was removed. Comments and blank lines are preserved.
func RemoveMatching(lines []string, pattern string) ([]string, bool) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return lines, false
	}
	out := make([]string, 0, len(lines))
	removed := false
	for _, ln := range lines {
		if normalizePattern(ln) == pattern {
			removed = true
			continue
		}
		out = append(out, ln)
	}
	return out, removed
}

// normalizePattern returns the comparison key for a line: lower-
// case, no inline comment, no surrounding whitespace. Returns ""
// for blank or pure-comment lines.
func normalizePattern(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	if i := strings.Index(t, " #"); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	return strings.ToLower(t)
}
