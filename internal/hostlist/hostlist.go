// Package hostlist implements the flat allow/deny list format used
// for the fast-path decision tier. Entries are simple text lines:
//
//	host[:port][/path]
//
// with `*` wildcards as documented in DESIGN.md §10.8. The fast-
// path lists are evaluated BEFORE the YAML rule engine and BEFORE
// the LLM advisor; matched requests skip both.
package hostlist

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Pattern is one parsed line.
type Pattern struct {
	Source string // "<file>:<line>" for diagnostics
	Raw    string // original line, trimmed

	// Method matching (closes #85):
	//   anyMethod: pattern had no method prefix or used `*`
	//   method:    uppercase HTTP verb when explicit (e.g., "GET")
	anyMethod bool
	method    string

	// Scheme matching:
	//   anyScheme: pattern had no `<scheme>://` prefix
	//   scheme:    "http" or "https" when explicit; matched exactly
	anyScheme bool
	scheme    string

	// Host matching:
	//   wildcardAllHosts: pattern was bare "*"
	//   wildcardPrefix:   pattern was "*.example.com" — match any
	//                     subdomain (one or more labels)
	//   exactHost:        host must equal this string
	wildcardAllHosts bool
	wildcardPrefix   bool
	hostSuffix       string // ".example.com" when wildcardPrefix
	exactHost        string

	// Port matching:
	//   anyPort: omitted or "*"
	//   port:    exact int
	anyPort bool
	port    int

	// Path matching:
	//   anyPath:    omitted or path was "/*"
	//   pathPrefix: line ended with "/*" — match the prefix
	//   exactPath:  match the path string exactly
	anyPath    bool
	pathPrefix string // "/api/" when matchPrefix true
	exactPath  string
	matchPrefix bool
}

// HostList is a parsed allow- or deny-list.
type HostList struct {
	Name     string // "allow" / "deny" — used in audit log decision_source
	Patterns []Pattern
}

// LoadInline parses pre-extracted entry strings (e.g., from
// `lists.allow` / `lists.deny` in trollbridge.yaml) and returns a
// merged HostList. Empty strings and `#`-prefixed comments are
// skipped, mirroring LoadFiles. Per-entry diagnostic source uses
// the provided sourceLabel (e.g., "trollbridge.yaml:lists.allow").
func LoadInline(name, sourceLabel string, entries []string) (*HostList, error) {
	out := &HostList{Name: name}
	for i, raw := range entries {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		pat, err := parsePattern(line)
		if err != nil {
			return nil, fmt.Errorf("hostlist parse %s[%d]: %s: %w", sourceLabel, i, line, err)
		}
		pat.Source = fmt.Sprintf("%s[%d]", sourceLabel, i)
		out.Patterns = append(out.Patterns, pat)
	}
	return out, nil
}

// LoadFiles reads the supplied files (in order) and returns one
// merged HostList. Returns an error if any file cannot be read or
// any line cannot be parsed.
//
// Deprecated: v2 schema stores lists inline in trollbridge.yaml; use
// LoadInline. Kept temporarily for tests that still operate on the
// legacy .txt format.
func LoadFiles(name string, paths []string) (*HostList, error) {
	out := &HostList{Name: name}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("hostlist load %s: %w", p, err)
		}
		sc := bufio.NewScanner(f)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Strip inline comments after whitespace + #.
			if i := strings.Index(line, " #"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			pat, err := parsePattern(line)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("hostlist parse %s:%d: %s: %w", p, lineNo, line, err)
			}
			pat.Source = fmt.Sprintf("%s:%d", p, lineNo)
			out.Patterns = append(out.Patterns, pat)
		}
		if err := sc.Err(); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
	}
	return out, nil
}

// parsePattern accepts a single trimmed, non-empty line. The
// supported shape is:
//
//	[<METHOD>|*] [<scheme>://]<host>[:<port>][<path>]
//
// where the optional leading METHOD token is an uppercase HTTP
// verb (or `*` for any). An absent prefix means "any method"
// (anyMethod=true), preserving backward compatibility with
// pre-#85 pattern files.
func parsePattern(s string) (Pattern, error) {
	p := Pattern{Raw: s}

	// Optional leading method token. Format: first whitespace-
	// separated token is `*` or uppercase letters. We probe before
	// the scheme parse because methods precede `<scheme>://`.
	rest := s
	if sp := strings.IndexByte(rest, ' '); sp > 0 {
		head := rest[:sp]
		if head == "*" {
			p.anyMethod = true
			rest = strings.TrimSpace(rest[sp+1:])
		} else if isUppercaseLetters(head) {
			p.method = head
			rest = strings.TrimSpace(rest[sp+1:])
		} else {
			// First token is not a method; treat the whole line as
			// the host part and set anyMethod.
			p.anyMethod = true
		}
	} else {
		p.anyMethod = true
	}

	// Optional <scheme>:// prefix.
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme := strings.ToLower(rest[:i])
		switch scheme {
		case "http", "https":
			p.scheme = scheme
		default:
			return p, fmt.Errorf("scheme must be http or https; got %q", scheme)
		}
		rest = rest[i+3:]
	} else {
		p.anyScheme = true
	}

	// Split off path first.
	hostport := rest
	pathPart := ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport = rest[:i]
		pathPart = rest[i:]
	}

	// Split host:port.
	host := hostport
	portPart := ""
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		portPart = hostport[i+1:]
	}

	// Host.
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case host == "":
		return p, fmt.Errorf("empty host")
	case host == "*":
		p.wildcardAllHosts = true
	case strings.HasPrefix(host, "*."):
		p.wildcardPrefix = true
		p.hostSuffix = host[1:] // ".example.com"
		if strings.Contains(p.hostSuffix[1:], "*") {
			return p, fmt.Errorf("host wildcard supports only `*.<suffix>` or bare `*`")
		}
	case strings.Contains(host, "*"):
		return p, fmt.Errorf("host wildcard supports only `*.<suffix>` or bare `*`")
	default:
		p.exactHost = host
	}

	// Port.
	switch portPart {
	case "", "*":
		p.anyPort = true
	default:
		port, err := strconv.Atoi(portPart)
		if err != nil || port < 1 || port > 65535 {
			return p, fmt.Errorf("invalid port %q", portPart)
		}
		p.port = port
	}

	// Path.
	switch {
	case pathPart == "" || pathPart == "/*":
		p.anyPath = true
	case strings.HasSuffix(pathPart, "/*"):
		p.matchPrefix = true
		p.pathPrefix = strings.TrimSuffix(pathPart, "/*") + "/"
	case strings.Contains(pathPart, "*"):
		return p, fmt.Errorf("path wildcard supports only trailing `/*`")
	default:
		p.exactPath = pathPart
	}

	return p, nil
}

// Match returns the matching Pattern (and true) if any pattern
// fires on the supplied (method, scheme, host, port, path). Pass
// scheme="" when the request is a CONNECT and no scheme is yet
// known; only patterns with no scheme constraint will match.
// Method comparison is case-insensitive — request methods are
// typically uppercase but lowercase operator typos still match.
// Patterns without a method prefix match any method (#85).
func (h *HostList) Match(method, scheme, host string, port int, path string) (Pattern, bool) {
	if h == nil {
		return Pattern{}, false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = "/"
	}
	for _, p := range h.Patterns {
		if !matchMethodPattern(p, method) {
			continue
		}
		if !matchSchemePattern(p, scheme) {
			continue
		}
		if !matchHostPattern(p, host) {
			continue
		}
		if !p.anyPort && p.port != port {
			continue
		}
		if !matchPathPattern(p, path) {
			continue
		}
		return p, true
	}
	return Pattern{}, false
}

func matchMethodPattern(p Pattern, method string) bool {
	if p.anyMethod {
		return true
	}
	return method == p.method
}

// isUppercaseLetters reports whether s is non-empty and consists
// entirely of uppercase A-Z. Used by parsePattern to recognise
// the optional method-prefix token (#85).
func isUppercaseLetters(s string) bool {
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

func matchSchemePattern(p Pattern, scheme string) bool {
	if p.anyScheme {
		return true
	}
	return scheme == p.scheme
}

func matchHostPattern(p Pattern, host string) bool {
	switch {
	case p.wildcardAllHosts:
		return true
	case p.wildcardPrefix:
		// Match suffix and require at least one label before it.
		// "*.example.com" → suffix ".example.com"; host must end
		// with that AND have something before it.
		return strings.HasSuffix(host, p.hostSuffix) && len(host) > len(p.hostSuffix)
	default:
		return host == p.exactHost
	}
}

func matchPathPattern(p Pattern, path string) bool {
	switch {
	case p.anyPath:
		return true
	case p.matchPrefix:
		return strings.HasPrefix(path, p.pathPrefix)
	default:
		return path == p.exactPath
	}
}

// Subsumes reports whether the pattern `pattern` covers every request
// the pattern `entry` would — i.e. once `pattern` is on a list, `entry`
// on the same list is redundant. Used to prune the specific entries a
// generalization replaces (#177): a generalized pattern may widen the
// method (to `*`), drop the port, wildcard a trailing path segment, or
// wildcard the hostname, and each of those must be recognized as
// "covers the narrower entry." Conservative: if either string fails to
// parse, returns false (keep the entry).
func Subsumes(pattern, entry string) bool {
	p, err := parsePattern(pattern)
	if err != nil {
		return false
	}
	e, err := parsePattern(entry)
	if err != nil {
		return false
	}
	return subsumes(p, e)
}

// subsumes is the per-axis "p is more-general-or-equal than e" test.
func subsumes(p, e Pattern) bool {
	if !p.anyMethod && (e.anyMethod || e.method != p.method) {
		return false
	}
	if !p.anyScheme && (e.anyScheme || e.scheme != p.scheme) {
		return false
	}
	if !hostSubsumes(p, e) {
		return false
	}
	if !p.anyPort && (e.anyPort || e.port != p.port) {
		return false
	}
	if !pathSubsumes(p, e) {
		return false
	}
	return true
}

func hostSubsumes(p, e Pattern) bool {
	switch {
	case p.wildcardAllHosts:
		return true
	case p.wildcardPrefix:
		switch {
		case e.wildcardAllHosts:
			return false // e is broader than p
		case e.wildcardPrefix:
			// e = *.<eSuffix> ⊆ p = *.<pSuffix> iff eSuffix ends with
			// pSuffix (e.g. p=*.example.com ⊇ e=*.api.example.com).
			return strings.HasSuffix(e.hostSuffix, p.hostSuffix)
		default: // e.exactHost
			return strings.HasSuffix(e.exactHost, p.hostSuffix) && len(e.exactHost) > len(p.hostSuffix)
		}
	default: // p.exactHost
		return !e.wildcardAllHosts && !e.wildcardPrefix && e.exactHost == p.exactHost
	}
}

func pathSubsumes(p, e Pattern) bool {
	switch {
	case p.anyPath:
		return true
	case p.matchPrefix:
		switch {
		case e.anyPath:
			return false // e matches all paths; p only a prefix
		case e.matchPrefix:
			return strings.HasPrefix(e.pathPrefix, p.pathPrefix)
		default: // e.exactPath
			return strings.HasPrefix(e.exactPath, p.pathPrefix)
		}
	default: // p.exactPath
		return !e.anyPath && !e.matchPrefix && e.exactPath == p.exactPath
	}
}
