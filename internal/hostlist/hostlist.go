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

// LoadFiles reads the supplied files (in order) and returns one
// merged HostList. Returns an error if any file cannot be read or
// any line cannot be parsed.
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

// parsePattern accepts a single trimmed, non-empty line.
func parsePattern(s string) (Pattern, error) {
	p := Pattern{Raw: s}

	// Split off path first.
	hostport := s
	pathPart := ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		hostport = s[:i]
		pathPart = s[i:]
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
// fires on the supplied (host, port, path).
func (h *HostList) Match(host string, port int, path string) (Pattern, bool) {
	if h == nil {
		return Pattern{}, false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = "/"
	}
	for _, p := range h.Patterns {
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
