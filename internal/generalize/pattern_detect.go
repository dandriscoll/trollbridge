package generalize

import (
	"fmt"
	"sort"
	"strings"
)

// AxisPatternPrefix is the axis-name prefix for pattern-shaped
// candidates. The full axis name is `pattern:<pattern_name>`, e.g.
// `pattern:azure_arm`. The prefix lets advisor axisPriority and the
// TUI card distinguish pattern axes from flat ones without enumerating
// every concrete pattern name.
const AxisPatternPrefix = "pattern:"

// Recognizer is the function shape DetectPattern uses to recognize a
// URL against a registry of patterns. Wired by the suggestion Manager
// from the server's pattern.Registry. Returns (name, components, true)
// if a pattern matched; (_, _, false) otherwise.
//
// Pattern recognition is expected to be panic-safe (the registry
// wraps each pattern's Match in defer/recover); a recognizer that
// panics on a particular entry causes that entry to be skipped from
// pattern detection but does not abort the detector.
type Recognizer func(host string, port int, scheme, path string) (name string, components map[string]string, ok bool)

// DetectPattern recognizes entries against the supplied Recognizer
// and emits one Candidate per group of ≥2 entries that share a
// (list, pattern, method) tuple. Within each group the constant
// components across the source set are captured; varying components
// are dropped from the candidate's PatternMatch.Components map (and
// will appear as wildcards in the resulting YAML rule).
//
// allow and deny are processed independently; per-list isolation
// matches the convention in the other detectors.
//
// The threshold (≥2 source entries) matches DetectMethod,
// DetectURLSegment, etc. A single recognized entry produces no
// candidate.
func DetectPattern(allow, deny []string, recognize Recognizer) []Candidate {
	if recognize == nil {
		return nil
	}
	var out []Candidate
	for _, l := range []struct {
		name    string
		entries []string
	}{{"allow", allow}, {"deny", deny}} {
		out = append(out, detectPatternForList(l.entries, l.name, recognize)...)
	}
	return out
}

// patternGroupKey identifies one detection group: same list (already
// gated by the caller), same recognized pattern, same method.
type patternGroupKey struct {
	pattern string
	method  string
}

type patternMember struct {
	raw        string
	components map[string]string
}

func detectPatternForList(entries []string, list string, recognize Recognizer) []Candidate {
	groups := map[patternGroupKey][]patternMember{}
	for _, e := range entries {
		p := parseEntry(e)
		if !p.ok {
			continue
		}
		name, comps, ok := recognize(p.host, p.port, p.scheme, p.path)
		if !ok {
			continue
		}
		// Normalize method: "*" sentinel from parseEntry means
		// no-method-prefix in the list entry. For pattern grouping
		// we treat that as "any method"; rules emit it as the
		// empty method clause.
		method := p.method
		if method == "*" {
			method = ""
		}
		key := patternGroupKey{pattern: name, method: method}
		groups[key] = append(groups[key], patternMember{raw: p.raw, components: comps})
	}

	// Stable iteration order for determinism (test fixtures depend
	// on this).
	keys := make([]patternGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pattern != keys[j].pattern {
			return keys[i].pattern < keys[j].pattern
		}
		return keys[i].method < keys[j].method
	})

	var out []Candidate
	for _, k := range keys {
		members := groups[k]
		if len(members) < 2 {
			continue
		}
		constants := intersectComponents(members)
		varying := varyingComponents(members, constants)
		sources := make([]string, 0, len(members))
		for _, m := range members {
			sources = append(sources, m.raw)
		}
		sort.Strings(sources)
		out = append(out, Candidate{
			Axis:             Axis(AxisPatternPrefix + k.pattern),
			List:             list,
			SourceEntries:    sources,
			SuggestedPattern: renderPatternSummary(k.pattern, k.method, constants, varying),
			PatternMatch: &PatternCandidateInfo{
				Pattern:    k.pattern,
				Components: constants,
				Method:     k.method,
			},
		})
	}
	return out
}

// intersectComponents returns the component keys whose value is the
// same across every member, with that value. A component absent from
// any member is excluded. Empty-string values are preserved (the URL
// not carrying a component is a real, comparable state).
func intersectComponents(members []patternMember) map[string]string {
	if len(members) == 0 {
		return nil
	}
	// Start from the first member's component set.
	candidate := make(map[string]string, len(members[0].components))
	for k, v := range members[0].components {
		candidate[k] = v
	}
	for _, m := range members[1:] {
		for k, v := range candidate {
			mv, present := m.components[k]
			if !present || mv != v {
				delete(candidate, k)
			}
		}
	}
	return candidate
}

// varyingComponents returns the component keys that are NOT in
// constants (sorted for stable rendering).
func varyingComponents(members []patternMember, constants map[string]string) []string {
	seen := map[string]bool{}
	for _, m := range members {
		for k := range m.components {
			seen[k] = true
		}
	}
	for k := range constants {
		delete(seen, k)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func renderPatternSummary(pattern, method string, constants map[string]string, varying []string) string {
	var b strings.Builder
	b.WriteString(pattern)
	if method != "" {
		fmt.Fprintf(&b, " method=%s", method)
	}
	// Sort constant keys for deterministic rendering.
	keys := make([]string, 0, len(constants))
	for k := range constants {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := constants[k]
		if v == "" {
			v = `""`
		}
		fmt.Fprintf(&b, " %s=%s", k, v)
	}
	for _, k := range varying {
		fmt.Fprintf(&b, " %s=*", k)
	}
	return b.String()
}

// DetectAllWithRecognizer is DetectAll plus DetectPattern. Suggestion
// Manager calls this when a recognizer is wired; otherwise it falls
// through to DetectAll (which keeps the legacy three-detector behavior
// and the existing test surface intact).
func DetectAllWithRecognizer(allow, deny []string, recognize Recognizer) []Candidate {
	out := DetectAll(allow, deny)
	if recognize == nil {
		return out
	}
	out = append(out, DetectPattern(allow, deny, recognize)...)
	return out
}
