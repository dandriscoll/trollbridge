// Package llmtest is the trollbridge LLM-advisor regression framework
// (closes #133). It runs operator-defined fixture bundles against
// the real LLM advisor and asserts on the returned verdict +
// confidence, so prompt drift or model-version changes surface as
// failing tests rather than silent production drift.
//
// Concepts:
//
//   - Bundle: a YAML file declaring a set of test cases sharing a
//     directives prompt and an allow/deny list context.
//   - Case: one request fixture + an expected verdict band.
//   - Run: dispatches each case through an advisor.Provider and
//     reports per-case pass/fail.
//
// The runner is intentionally thin: it bypasses advisor.Service's
// caching + digest layer and calls advisor.Provider.Classify
// directly, so each test makes exactly one live LLM call.
//
// See llmtest/README.md for bundle format and operator workflow.
package llmtest

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Bundle is a top-level test fixture: shared LLM directives + lists
// context plus N cases. Each case sends one request through the
// advisor; the bundle's directives and lists are included in every
// per-case call so the LLM sees the operator's full policy.
type Bundle struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Directives is the operator-supplied system-prompt content,
	// included verbatim in every per-case advisor.Input.Directives.
	// Mirrors cfg.LLM.Directives in shape.
	Directives string `yaml:"directives"`

	// Lists.Allow and Lists.Deny are forwarded into every per-case
	// advisor.Input as AllowList / DenyList. The advisor's system
	// prompt names these to the LLM as the operator's policy hint.
	Lists BundleLists `yaml:"lists"`

	Cases []Case `yaml:"cases"`
}

// BundleLists declares the allow/deny patterns the bundle wants the
// LLM to consider. Matches `internal/advisor.Input.AllowList /
// DenyList` shape exactly.
type BundleLists struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Case is one fixture: request + expected verdict.
type Case struct {
	Name    string  `yaml:"name"`
	Request Request `yaml:"request"`
	Expect  Expect  `yaml:"expect"`
}

// Request carries the fields the advisor sees. Mirrors the relevant
// subset of advisor.Input — fields the operator typically pins in a
// regression fixture (method, host, port, path, identity,
// content-type).
type Request struct {
	Method      string            `yaml:"method"`
	Scheme      string            `yaml:"scheme"` // defaults to "https"
	Host        string            `yaml:"host"`
	Port        int               `yaml:"port"` // defaults to 443 for https, 80 for http
	Path        string            `yaml:"path"`
	Headers     map[string]string `yaml:"headers"`
	BodySummary map[string]any    `yaml:"body_summary"`
	Identity    string            `yaml:"identity"`
}

// Expect is the operator's assertion on the LLM's verdict. Verdict
// is mandatory; the confidence bands are optional.
//
//   - Verdict: one of "allow" / "deny" / "ask_user".
//   - MinConfidence / MaxConfidence: one of "low" / "medium" / "high".
//     When set, the actual confidence must fall in [Min, Max].
//
// Common patterns:
//   - "this MUST be deny with HIGH confidence" → verdict=deny,
//     min_confidence=high.
//   - "this is genuinely ambiguous" → verdict=ask_user OR
//     min_confidence=low max_confidence=medium against any verdict.
type Expect struct {
	Verdict       string `yaml:"verdict"`
	MinConfidence string `yaml:"min_confidence"`
	MaxConfidence string `yaml:"max_confidence"`
}

// Load reads a YAML bundle from disk. Strict decoding (KnownFields)
// catches typos in the bundle keys early.
func Load(path string) (*Bundle, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("llmtest: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("llmtest: decode %s: %w", path, err)
	}
	if b.Name == "" {
		return nil, fmt.Errorf("llmtest: %s: bundle.name is required", path)
	}
	if len(b.Cases) == 0 {
		return nil, fmt.Errorf("llmtest: %s: at least one case is required", path)
	}
	for i, c := range b.Cases {
		if c.Name == "" {
			return nil, fmt.Errorf("llmtest: %s: case[%d].name is required", path, i)
		}
		if c.Request.Method == "" || c.Request.Host == "" {
			return nil, fmt.Errorf("llmtest: %s: case %q: request.method and request.host are required", path, c.Name)
		}
		if c.Expect.Verdict == "" {
			return nil, fmt.Errorf("llmtest: %s: case %q: expect.verdict is required", path, c.Name)
		}
	}
	return &b, nil
}
