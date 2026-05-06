// Package policy implements the deterministic rule engine. See
// DESIGN.md §10.
package policy

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/dandriscoll/drawbridge/internal/types"
)

// Rule is a single match-and-effect entry. See DESIGN.md §8.3.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Priority    int      `yaml:"priority"`
	Match       Match    `yaml:"match"`
	Effect      string   `yaml:"effect"`
	Modifiers   []string `yaml:"modifiers"`
	Expires     string   `yaml:"expires"`
}

// Match is the AND-combined conjunction of clauses on a Rule.
type Match struct {
	Host         StringOrList `yaml:"host"`
	Port         IntOrList    `yaml:"port"`
	Method       StringOrList `yaml:"method"`
	Path         string       `yaml:"path"`
	PathPrefix   string       `yaml:"path_prefix"`
	PathRegex    string       `yaml:"path_regex"`
	HeaderMatch  map[string]string `yaml:"header_match"`
	Identity     string       `yaml:"identity"`
	Tool         string       `yaml:"tool"`
	ContentType  string       `yaml:"content_type"`
	BodyPattern  string       `yaml:"body_pattern"`
}

// StringOrList accepts either a single string or a list of strings
// in YAML; it normalizes to a slice.
type StringOrList []string

// UnmarshalYAML implements yaml.Unmarshaler for StringOrList.
func (s *StringOrList) UnmarshalYAML(unmarshal func(any) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*s = []string{single}
		return nil
	}
	var multi []string
	if err := unmarshal(&multi); err == nil {
		*s = multi
		return nil
	}
	return fmt.Errorf("StringOrList: not a string or string list")
}

// IntOrList accepts an int or list of ints in YAML.
type IntOrList []int

// UnmarshalYAML implements yaml.Unmarshaler for IntOrList.
func (s *IntOrList) UnmarshalYAML(unmarshal func(any) error) error {
	var single int
	if err := unmarshal(&single); err == nil {
		*s = []int{single}
		return nil
	}
	var multi []int
	if err := unmarshal(&multi); err == nil {
		*s = multi
		return nil
	}
	return fmt.Errorf("IntOrList: not an int or int list")
}

// matches returns true if the Rule's Match clauses all fire on the
// supplied RequestEvent.
func (r *Rule) matches(req *types.RequestEvent) bool {
	m := &r.Match

	if len(m.Host) > 0 && !matchHost(m.Host, req.Host) {
		return false
	}
	if len(m.Port) > 0 && !containsInt(m.Port, req.Port) {
		return false
	}
	if len(m.Method) > 0 && !containsStringFold(m.Method, req.Method) {
		return false
	}
	if m.Path != "" && req.Path != m.Path {
		return false
	}
	if m.PathPrefix != "" && !strings.HasPrefix(req.Path, m.PathPrefix) {
		return false
	}
	if m.PathRegex != "" {
		re, err := regexp.Compile(m.PathRegex)
		if err != nil || !re.MatchString(req.Path) {
			return false
		}
	}
	if m.Identity != "" && m.Identity != req.IdentityID {
		return false
	}
	for h, pattern := range m.HeaderMatch {
		if !headerMatches(req.Headers, h, pattern) {
			return false
		}
	}
	if m.ContentType != "" {
		if !strings.EqualFold(m.ContentType, req.Headers.Get("Content-Type")) {
			return false
		}
	}
	// body_pattern is Phase 2/3 (requires body inspection); ignore here.
	_ = m.Tool
	return true
}

// matchHost checks an exact-or-wildcard host match.
func matchHost(patterns []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsStringFold(haystack []string, needle string) bool {
	for _, v := range haystack {
		if strings.EqualFold(v, needle) {
			return true
		}
	}
	return false
}

func headerMatches(h http.Header, name, pattern string) bool {
	val := h.Get(name)
	if val == "" {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(val)
}
