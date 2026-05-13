package policy

import (
	"net/http"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// FuzzRuleRegex_PathRegex closes #104's "fuzz tests for rule regex"
// bullet. The match path compiles user-supplied regex via
// regexp.Compile (rule.go:123); a maliciously crafted PathRegex
// could either panic the compiler or run for a pathologically long
// time on a constructed input. The fuzzer's job is to surface
// either failure mode by feeding random patterns and inputs.
//
// Run: go test -fuzz=FuzzRuleRegex_PathRegex -fuzztime=30s ./internal/policy/
func FuzzRuleRegex_PathRegex(f *testing.F) {
	seeds := []struct{ pattern, path string }{
		{"^/api/v1/", "/api/v1/users"},
		{".*", ""},
		{"(a+)+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"},
		{"[", "/abc"},
		{`\d{1000}`, "1234567890"},
		{"", "/"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.path)
	}

	f.Fuzz(func(t *testing.T, pattern, path string) {
		// matchRequest must not panic regardless of pattern shape;
		// a regex compile error produces a non-match, not a crash.
		rule := Rule{
			ID:     "fuzz",
			Effect: "deny",
			Match: Match{
				PathRegex: pattern,
			},
		}
		req := &types.RequestEvent{
			Method:  "GET",
			Scheme:  "https",
			Host:    "example.com",
			Port:    443,
			Path:    path,
			Headers: http.Header{},
		}
		// rule.matches is the production helper; running it under
		// the fuzzer surfaces panics in the regex pipeline. We
		// don't assert on the bool — we assert on absence of panic.
		_ = rule.matches(req, evalContext{})
	})
}

// FuzzRuleRegex_BodyPattern is the body-pattern variant of the above.
// rule.go:157 compiles BodyPattern via regexp.Compile in the same
// shape; same risk class.
func FuzzRuleRegex_BodyPattern(f *testing.F) {
	seeds := []string{
		`"api_key"`,
		``,
		`(a+)+$`,
		`[`,
	}
	for _, p := range seeds {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		rule := Rule{
			ID:     "fuzz",
			Effect: "deny",
			Match: Match{
				BodyPattern: pattern,
			},
		}
		req := &types.RequestEvent{
			Method:     "POST",
			Scheme:     "https",
			Host:       "example.com",
			Port:       443,
			Path:       "/",
			Headers:    http.Header{},
			BodySample: []byte(`{"api_key":"sk-XXX"}`),
		}
		_ = rule.matches(req, evalContext{})
	})
}
