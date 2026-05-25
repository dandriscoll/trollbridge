// Package generalize detects opportunities to generalize across two
// or more entries on the operator's allow or deny list. The package
// is pure — every detector is a function from `[]string` (list
// entries) to `[]Candidate`. Lifecycle, decline-filtering, and the
// LLM-rank/narrate step live in internal/suggestion.
//
// Closed-set axes per issue #168:
//   - hostname_below_tld: api.example.com + auth.example.com → *.example.com
//   - url_segment:        /api/v1/users/123 + /api/v1/users/456 → /api/v1/users/*
//   - method:             GET /foo + POST /foo → * /foo
//
// An ip_block axis (10.0.0.1 + 10.0.0.2 → 10.0.0.0/24) was removed in #181:
// hostlist has no CIDR host shape, so an accepted /24 pattern matched nothing.
package generalize

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Axis names the three allowed generalization classes. The set is
// closed; adding a fourth axis means updating Axes AND the dispatch
// in DetectAll.
type Axis string

const (
	AxisHostnameBelowTLD Axis = "hostname_below_tld"
	AxisURLSegment       Axis = "url_segment"
	AxisMethod           Axis = "method"
)

// Axes is the closed set of supported generalization classes. The
// presence test in generalize_test.go asserts len(Axes) == 3 and
// that DetectAll dispatches every axis in this slice.
var Axes = []Axis{
	AxisHostnameBelowTLD,
	AxisURLSegment,
	AxisMethod,
}

// Candidate is one generalization opportunity. SourceEntries is the
// sorted, canonical set of original list entries that motivated the
// suggestion. CanonicalKey() is the dedup key used by the decline
// filter and by per-session axis-cycle state.
type Candidate struct {
	Axis             Axis
	List             string // "allow" or "deny"
	SourceEntries    []string
	SuggestedPattern string
}

// CanonicalKey returns the sorted-canonical form of SourceEntries
// joined with NUL. Two Candidates with the same source set produce
// the same key regardless of axis or suggested pattern.
func (c Candidate) CanonicalKey() string {
	sorted := append([]string(nil), c.SourceEntries...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\x00")
}

// DetectAll runs every detector on allow then deny and returns the
// concatenated candidates. Allow and deny are NEVER mixed within a
// single Candidate; per-list isolation is part of the security
// model (a deny is more restrictive than an allow).
func DetectAll(allow, deny []string) []Candidate {
	var out []Candidate
	for _, list := range []struct {
		name    string
		entries []string
	}{{"allow", allow}, {"deny", deny}} {
		out = append(out, DetectMethod(list.entries, list.name)...)
		out = append(out, DetectURLSegment(list.entries, list.name)...)
		out = append(out, DetectHostnameBelowTLD(list.entries, list.name)...)
	}
	return out
}

// parsed is the structured form of one list entry. Detectors group
// on these fields rather than re-parsing strings.
type parsed struct {
	raw    string
	method string // upper-case; "*" for any
	scheme string // "http" / "https" / ""
	host   string // hostname or IP literal (lowercased)
	port   int    // 0 when unspecified
	path   string // includes leading slash; "" for CONNECT-style
	ok     bool
	// isIP reports whether host is an IPv4 literal (we only do IP
	// block grouping over v4 in v1; v6 is forward-compat in the API
	// but not currently grouped because operator allow/deny lists
	// rarely include v6 literals).
	isIP bool
}

// parseEntry parses one list entry into structured form. Returns
// parsed{ok=false} for malformed entries; callers skip those.
//
// Pattern shape: `[METHOD ]URL` where METHOD is `*` or an
// upper-case verb. URL is `[scheme://]host[:port][path]`.
// Wildcards in the URL (`*`) make the entry ineligible for
// generalization — generalize is for concrete entries.
func parseEntry(raw string) parsed {
	out := parsed{raw: strings.TrimSpace(raw)}
	if out.raw == "" {
		return out
	}
	rest := out.raw
	// Method prefix is the leading token IF it is "*" or all
	// uppercase ASCII (and is followed by whitespace).
	if i := strings.IndexByte(rest, ' '); i > 0 {
		head := rest[:i]
		if head == "*" || isAllUpperASCII(head) {
			out.method = head
			rest = strings.TrimSpace(rest[i+1:])
		}
	}
	if out.method == "" {
		out.method = "*"
	}
	if strings.ContainsRune(rest, '*') {
		// Concrete-only generalization; skip wildcard entries.
		return out
	}
	// Scheme.
	if i := strings.Index(rest, "://"); i >= 0 {
		out.scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
	}
	// Path.
	var hostport string
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport = rest[:i]
		out.path = rest[i:]
	} else {
		hostport = rest
	}
	// host:port. IPv6 literals are bracketed.
	host, port, err := splitHostPort(hostport)
	if err != nil || host == "" {
		return out
	}
	out.host = strings.ToLower(host)
	out.port = port
	out.isIP = net.ParseIP(out.host) != nil && net.ParseIP(out.host).To4() != nil
	// Canonicalize scheme-default ports so :443 / :80 / unspecified
	// group together cleanly under the same scheme.
	if out.port != 0 {
		switch out.scheme {
		case "https":
			if out.port == 443 {
				out.port = 0
			}
		case "http":
			if out.port == 80 {
				out.port = 0
			}
		}
	}
	out.ok = true
	return out
}

func isAllUpperASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func splitHostPort(hp string) (string, int, error) {
	if hp == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	// Bracketed IPv6.
	if strings.HasPrefix(hp, "[") {
		j := strings.IndexByte(hp, ']')
		if j < 0 {
			return "", 0, fmt.Errorf("unterminated bracket")
		}
		host := hp[1:j]
		rest := hp[j+1:]
		port := 0
		if strings.HasPrefix(rest, ":") {
			n, err := strconv.Atoi(rest[1:])
			if err != nil {
				return "", 0, err
			}
			port = n
		}
		return host, port, nil
	}
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		// Disambiguate: pure-IPv6 (multiple colons) cannot be split
		// this way. parseEntry already requires bracketing for IPv6
		// with ports; bare ipv6 without port lands here with multiple
		// colons → treat the whole string as the host.
		if strings.Count(hp, ":") > 1 {
			return hp, 0, nil
		}
		n, err := strconv.Atoi(hp[i+1:])
		if err != nil {
			return hp, 0, nil
		}
		return hp[:i], n, nil
	}
	return hp, 0, nil
}

// formatHost renders host[:port], bracketing IPv6 literals.
func formatHost(host string, port int) string {
	if strings.ContainsRune(host, ':') {
		host = "[" + host + "]"
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// renderPattern returns the canonical pattern string for the four
// shapes of generalization output. Scheme is preserved; port is
// only emitted when non-default.
func renderPattern(method, scheme, hostExpr, pathExpr string) string {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	if scheme != "" {
		sb.WriteString(scheme)
		sb.WriteString("://")
	}
	sb.WriteString(hostExpr)
	sb.WriteString(pathExpr)
	return sb.String()
}

// groupKey for the method axis: everything except method.
func groupKeyMethod(p parsed) string {
	return p.scheme + "|" + formatHost(p.host, p.port) + "|" + p.path
}

// DetectMethod groups entries by (scheme, host, port, path); emits
// one Candidate per group with ≥2 distinct methods.
func DetectMethod(entries []string, list string) []Candidate {
	by := map[string][]parsed{}
	for _, e := range entries {
		p := parseEntry(e)
		if !p.ok {
			continue
		}
		by[groupKeyMethod(p)] = append(by[groupKeyMethod(p)], p)
	}
	var out []Candidate
	for _, group := range by {
		methods := uniqueMethods(group)
		// "≥2 existing URLs in the list" — the directive's rule.
		// Two entries with the same method don't qualify; two
		// entries with DIFFERENT methods do.
		if len(group) < 2 || len(methods) < 2 {
			continue
		}
		sources := rawSorted(group)
		head := group[0]
		pattern := renderPattern("*", head.scheme, formatHost(head.host, head.port), head.path)
		out = append(out, Candidate{
			Axis:             AxisMethod,
			List:             list,
			SourceEntries:    sources,
			SuggestedPattern: pattern,
		})
	}
	return out
}

// DetectURLSegment groups entries by (method, scheme, host, port,
// common-path-prefix-up-to-last-segment); emits one Candidate per
// group with ≥2 entries that differ ONLY in their final path
// segment.
func DetectURLSegment(entries []string, list string) []Candidate {
	type bucket struct {
		method, scheme, host string
		port                 int
		prefix               string
		members              []parsed
	}
	by := map[string]*bucket{}
	for _, e := range entries {
		p := parseEntry(e)
		if !p.ok || p.path == "" {
			continue
		}
		// Drop trailing slash to give path "/a/b/" and "/a/b" the
		// same prefix.
		path := strings.TrimRight(p.path, "/")
		// Need at least one separator (so the path has a "trailing
		// segment" to wildcard).
		i := strings.LastIndexByte(path, '/')
		if i < 0 {
			continue
		}
		prefix := path[:i]
		key := p.method + "|" + p.scheme + "|" + formatHost(p.host, p.port) + "|" + prefix
		b := by[key]
		if b == nil {
			b = &bucket{method: p.method, scheme: p.scheme, host: p.host, port: p.port, prefix: prefix}
			by[key] = b
		}
		b.members = append(b.members, p)
	}
	var out []Candidate
	for _, b := range by {
		if len(b.members) < 2 {
			continue
		}
		// Require the trailing segments to differ — two identical
		// entries should not count as "two URLs".
		segs := map[string]struct{}{}
		for _, m := range b.members {
			path := strings.TrimRight(m.path, "/")
			i := strings.LastIndexByte(path, '/')
			segs[path[i+1:]] = struct{}{}
		}
		if len(segs) < 2 {
			continue
		}
		sources := rawSorted(b.members)
		pattern := renderPattern(b.method, b.scheme, formatHost(b.host, b.port), b.prefix+"/*")
		out = append(out, Candidate{
			Axis:             AxisURLSegment,
			List:             list,
			SourceEntries:    sources,
			SuggestedPattern: pattern,
		})
	}
	return out
}

// DetectHostnameBelowTLD groups entries by (method, scheme, port,
// path) and a publicsuffix-aware parent suffix; emits one Candidate
// per group of ≥2 hosts that share a common parent BELOW their
// public suffix. Hosts at-or-below the public suffix itself are
// rejected (no *.co.uk).
func DetectHostnameBelowTLD(entries []string, list string) []Candidate {
	type bucket struct {
		method, scheme string
		port           int
		path           string
		parent         string
		members        []parsed
	}
	by := map[string]*bucket{}
	for _, e := range entries {
		p := parseEntry(e)
		if !p.ok || p.isIP {
			continue
		}
		parent := parentBelowPublicSuffix(p.host)
		if parent == "" {
			continue
		}
		// Reject hosts that ARE the parent — generalizing requires
		// distinct subdomains.
		if p.host == parent {
			continue
		}
		key := p.method + "|" + p.scheme + "|" + strconv.Itoa(p.port) + "|" + p.path + "|" + parent
		b := by[key]
		if b == nil {
			b = &bucket{method: p.method, scheme: p.scheme, port: p.port, path: p.path, parent: parent}
			by[key] = b
		}
		b.members = append(b.members, p)
	}
	var out []Candidate
	for _, b := range by {
		hosts := map[string]struct{}{}
		for _, m := range b.members {
			hosts[m.host] = struct{}{}
		}
		if len(hosts) < 2 {
			continue
		}
		sources := rawSorted(b.members)
		hostExpr := "*." + b.parent
		if b.port != 0 {
			hostExpr += ":" + strconv.Itoa(b.port)
		}
		pattern := renderPattern(b.method, b.scheme, hostExpr, b.path)
		out = append(out, Candidate{
			Axis:             AxisHostnameBelowTLD,
			List:             list,
			SourceEntries:    sources,
			SuggestedPattern: pattern,
		})
	}
	return out
}

// parentBelowPublicSuffix returns the deepest registrable parent of
// host, e.g. "api.example.com" → "example.com", "a.b.example.co.uk"
// → "b.example.co.uk". Returns "" when the host is at or below the
// public suffix itself (so a wildcard would over-broaden).
//
// We use the ETLD+1 ("EffectiveTLDPlusOne") as the anchor: a host
// is groupable when it has at least one label more specific than
// its eTLD+1. The wildcard parent is the host with its leftmost
// label removed, AS LONG AS that strip leaves at least the
// registrable domain intact.
func parentBelowPublicSuffix(host string) string {
	host = strings.TrimRight(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	if host == etldPlusOne {
		// Host is the registrable domain itself; can't wildcard
		// without crossing into the public suffix.
		return ""
	}
	i := strings.IndexByte(host, '.')
	if i < 0 {
		return ""
	}
	parent := host[i+1:]
	// Parent must not be shorter than the eTLD+1 (would mean we
	// crossed into the public suffix).
	if len(parent) < len(etldPlusOne) {
		return ""
	}
	return parent
}

// GeneralizeOne emits one Candidate per applicable generalization axis
// for a SINGLE concrete entry, in stable axis order (url_segment,
// hostname_below_tld, method). Unlike the DetectAll detectors
// — which require ≥2 grouped entries — this powers the URLs-pane
// single-select `g` (#170): the operator selects one entry and rotates
// the axis options. SourceEntries is the single entry. Returns nil for
// wildcard/malformed entries or when no axis applies.
func GeneralizeOne(entry, list string) []Candidate {
	p := parseEntry(entry)
	if !p.ok {
		return nil
	}
	src := []string{p.raw}
	var out []Candidate
	// url_segment: wildcard the trailing path segment.
	if p.path != "" {
		path := strings.TrimRight(p.path, "/")
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			pattern := renderPattern(p.method, p.scheme, formatHost(p.host, p.port), path[:i]+"/*")
			out = append(out, Candidate{Axis: AxisURLSegment, List: list, SourceEntries: src, SuggestedPattern: pattern})
		}
	}
	// hostname_below_tld: wildcard the leftmost label below the eTLD+1.
	if !p.isIP {
		if parent := parentBelowPublicSuffix(p.host); parent != "" && parent != p.host {
			hostExpr := "*." + parent
			if p.port != 0 {
				hostExpr += ":" + strconv.Itoa(p.port)
			}
			pattern := renderPattern(p.method, p.scheme, hostExpr, p.path)
			out = append(out, Candidate{Axis: AxisHostnameBelowTLD, List: list, SourceEntries: src, SuggestedPattern: pattern})
		}
	}
	// method: widen a concrete verb to any.
	if p.method != "*" {
		pattern := renderPattern("*", p.scheme, formatHost(p.host, p.port), p.path)
		out = append(out, Candidate{Axis: AxisMethod, List: list, SourceEntries: src, SuggestedPattern: pattern})
	}
	return out
}

func uniqueMethods(group []parsed) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range group {
		out[p.method] = struct{}{}
	}
	return out
}

func rawSorted(group []parsed) []string {
	out := make([]string, 0, len(group))
	for _, p := range group {
		out = append(out, p.raw)
	}
	sort.Strings(out)
	return out
}
