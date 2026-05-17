package llmtest

import (
	"context"
	"fmt"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// Result is the outcome of one case running through the advisor.
type Result struct {
	CaseName string
	Pass     bool
	Output   advisor.Output
	// Reason is the human-readable mismatch description when
	// Pass==false; empty on success.
	Reason string
}

// Run dispatches every case in b through prov.Classify and returns
// the per-case Result. Each Provider call is one live LLM request.
//
// The runner is non-aborting on per-case failures: a single failing
// case does not stop the bundle. Callers can decide how to surface
// aggregate failure (e.g., a Go test's t.Errorf per case so all
// mismatches print in one run).
func Run(ctx context.Context, prov advisor.Provider, b *Bundle) []Result {
	results := make([]Result, 0, len(b.Cases))
	for _, c := range b.Cases {
		in := buildInput(b, c)
		out, err := prov.Classify(ctx, in)
		if err != nil {
			results = append(results, Result{
				CaseName: c.Name,
				Pass:     false,
				Reason:   fmt.Sprintf("classify error: %v", err),
			})
			continue
		}
		r := Result{CaseName: c.Name, Output: out}
		if reason := check(out, c.Expect); reason != "" {
			r.Pass = false
			r.Reason = reason
		} else {
			r.Pass = true
		}
		results = append(results, r)
	}
	return results
}

// buildInput composes the per-case advisor.Input from the bundle's
// shared directives + lists and the case's request fixture. Scheme
// and port get sensible defaults so bundles can omit them.
func buildInput(b *Bundle, c Case) advisor.Input {
	scheme := c.Request.Scheme
	if scheme == "" {
		scheme = "https"
	}
	port := c.Request.Port
	if port == 0 {
		port = 443
		if scheme == "http" {
			port = 80
		}
	}
	return advisor.Input{
		Method:          c.Request.Method,
		Scheme:          scheme,
		Host:            c.Request.Host,
		Port:            port,
		Path:            c.Request.Path,
		HeadersRedacted: c.Request.Headers,
		BodySummary:     c.Request.BodySummary,
		Identity:        c.Request.Identity,
		AllowList:       b.Lists.Allow,
		DenyList:        b.Lists.Deny,
		Directives:      b.Directives,
	}
}

// check compares the actual Output against the expected band.
// Returns "" on pass, a human-readable mismatch reason on fail.
func check(out advisor.Output, e Expect) string {
	if e.Verdict != "" && !strings.EqualFold(out.Effect, e.Verdict) {
		return fmt.Sprintf("verdict mismatch: got %q, want %q (reason=%q, confidence=%q)",
			out.Effect, e.Verdict, out.Reason, out.Confidence)
	}
	if e.MinConfidence != "" {
		if !confidenceAtLeast(out.Confidence, e.MinConfidence) {
			return fmt.Sprintf("confidence below floor: got %q, want >= %q (verdict=%q reason=%q)",
				out.Confidence, e.MinConfidence, out.Effect, out.Reason)
		}
	}
	if e.MaxConfidence != "" {
		if confidenceAbove(out.Confidence, e.MaxConfidence) {
			return fmt.Sprintf("confidence above ceiling: got %q, want <= %q (verdict=%q reason=%q)",
				out.Confidence, e.MaxConfidence, out.Effect, out.Reason)
		}
	}
	return ""
}

// confidenceOrder maps the advisor's confidence vocabulary to an
// ordered scale. Unknown values rank below "low" so a malformed
// confidence string fails any non-trivial assertion.
var confidenceOrder = map[string]int{"low": 1, "medium": 2, "high": 3}

func confidenceAtLeast(got, floor string) bool {
	g := confidenceOrder[strings.ToLower(strings.TrimSpace(got))]
	f := confidenceOrder[strings.ToLower(strings.TrimSpace(floor))]
	if g == 0 || f == 0 {
		return false
	}
	return g >= f
}

func confidenceAbove(got, ceiling string) bool {
	g := confidenceOrder[strings.ToLower(strings.TrimSpace(got))]
	c := confidenceOrder[strings.ToLower(strings.TrimSpace(ceiling))]
	if g == 0 || c == 0 {
		return false
	}
	return g > c
}
