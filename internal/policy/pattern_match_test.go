package policy

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// stubValidator is a minimal PatternValidator for engine load tests
// in this package — implementing it inline avoids a policy →
// pattern import cycle (the real validator lives there).
type stubValidator struct {
	allowedPattern    string
	allowedComponents map[string]bool
}

func (s stubValidator) ValidateRuleMatch(name string, keys []string) error {
	if name != s.allowedPattern {
		return errf("unknown pattern %q", name)
	}
	for _, k := range keys {
		if !s.allowedComponents[k] {
			return errf("unknown component %q for pattern %s", k, name)
		}
	}
	return nil
}

func errf(format string, args ...any) error { return testError{format, args} }

type testError struct {
	format string
	args   []any
}

func (e testError) Error() string {
	s := e.format
	for _, a := range e.args {
		s = strings.Replace(s, "%q", quote(a), 1)
		s = strings.Replace(s, "%s", str(a), 1)
	}
	return s
}

func quote(v any) string { return "\"" + str(v) + "\"" }
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestEngine_PatternRule_MatchesWhenRecognized(t *testing.T) {
	p := writeRules(t, `
- id: allow-arm-reads-subA
  match:
    pattern: azure_arm
    components:
      subscription: SUB-A
    method: GET
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	// Wire the validator so the rule is re-validated. Allow only
	// "azure_arm" with the components used.
	if err := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{"subscription": true, "resource_group": true, "resource_type": true},
	}); err != nil {
		t.Fatalf("SetPatternValidator: %v", err)
	}

	cases := []struct {
		name   string
		req    *types.RequestEvent
		want   types.Effect
	}{
		{
			name: "matching ARM subscription request → allow",
			req: func() *types.RequestEvent {
				r := newReq("management.azure.com", "GET", "/subscriptions/SUB-A/...")
				r.MatchedPattern = &types.MatchedPattern{
					Name: "azure_arm",
					Components: map[string]string{
						"subscription":   "SUB-A",
						"resource_group": "rg1",
					},
				}
				return r
			}(),
			want: types.EffectAllow,
		},
		{
			name: "non-matching subscription → default deny",
			req: func() *types.RequestEvent {
				r := newReq("management.azure.com", "GET", "/subscriptions/SUB-B/...")
				r.MatchedPattern = &types.MatchedPattern{
					Name: "azure_arm",
					Components: map[string]string{"subscription": "SUB-B"},
				}
				return r
			}(),
			want: types.EffectDeny,
		},
		{
			name: "wrong method → default deny",
			req: func() *types.RequestEvent {
				r := newReq("management.azure.com", "DELETE", "/subscriptions/SUB-A/...")
				r.MatchedPattern = &types.MatchedPattern{
					Name: "azure_arm",
					Components: map[string]string{"subscription": "SUB-A"},
				}
				return r
			}(),
			want: types.EffectDeny,
		},
		{
			name: "request without MatchedPattern (non-ARM URL) → default deny",
			req:  newReq("api.github.com", "GET", "/foo"),
			want: types.EffectDeny,
		},
		{
			name: "request matched a DIFFERENT pattern → default deny",
			req: func() *types.RequestEvent {
				r := newReq("management.azure.com", "GET", "/subscriptions/SUB-A/...")
				r.MatchedPattern = &types.MatchedPattern{
					Name:       "azure_keyvault",
					Components: map[string]string{"vault": "myvault"},
				}
				return r
			}(),
			want: types.EffectDeny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Decide(tc.req)
			if d.Effect != tc.want {
				t.Fatalf("Effect = %s, want %s; reason=%q", d.Effect, tc.want, d.Reason)
			}
		})
	}
}

func TestEngine_PatternRule_WildcardComponent_MatchesAny(t *testing.T) {
	p := writeRules(t, `
- id: allow-arm-reads-any-sub
  match:
    pattern: azure_arm
    components:
      subscription: "*"
    method: GET
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{"subscription": true},
	}); err != nil {
		t.Fatalf("SetPatternValidator: %v", err)
	}
	r := newReq("management.azure.com", "GET", "/subscriptions/SUB-XYZ/...")
	r.MatchedPattern = &types.MatchedPattern{
		Name:       "azure_arm",
		Components: map[string]string{"subscription": "SUB-XYZ"},
	}
	if d := e.Decide(r); d.Effect != types.EffectAllow {
		t.Fatalf("wildcard subscription should match any value; got %s", d.Effect)
	}
}

func TestEngine_PatternRule_OmittedComponents_MatchesAny(t *testing.T) {
	p := writeRules(t, `
- id: allow-any-arm
  match:
    pattern: azure_arm
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{},
	}); err != nil {
		t.Fatalf("SetPatternValidator: %v", err)
	}
	r := newReq("management.azure.com", "GET", "/subscriptions/SUB-A/...")
	r.MatchedPattern = &types.MatchedPattern{
		Name:       "azure_arm",
		Components: map[string]string{"subscription": "SUB-A"},
	}
	if d := e.Decide(r); d.Effect != types.EffectAllow {
		t.Fatalf("rule with pattern: only should match any ARM request; got %s", d.Effect)
	}
}

func TestEngine_PatternRule_CaseInsensitiveComponent(t *testing.T) {
	p := writeRules(t, `
- id: allow-arm-mixedcase
  match:
    pattern: azure_arm
    components:
      resource_type: Microsoft.Compute/virtualMachines
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{"resource_type": true},
	}); err != nil {
		t.Fatalf("SetPatternValidator: %v", err)
	}
	r := newReq("management.azure.com", "GET", "/...")
	r.MatchedPattern = &types.MatchedPattern{
		Name:       "azure_arm",
		Components: map[string]string{"resource_type": "microsoft.compute/virtualmachines"},
	}
	if d := e.Decide(r); d.Effect != types.EffectAllow {
		t.Fatalf("case-insensitive component compare should match; got %s; reason=%q", d.Effect, d.Reason)
	}
}

func TestEngine_PatternRule_LoadError_ComponentsWithoutPattern(t *testing.T) {
	p := writeRules(t, `
- id: bogus
  match:
    components:
      subscription: SUB-A
  effect: allow
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil || !strings.Contains(err.Error(), "components") {
		t.Fatalf("expected load error mentioning components, got %v", err)
	}
}

func TestEngine_PatternRule_LoadError_UnknownPattern(t *testing.T) {
	p := writeRules(t, `
- id: bogus
  match:
    pattern: azure_armm
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	// Wire a validator that rejects "azure_armm" — Reload should
	// now error and the engine retains its prior (empty) rule set.
	rerr := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{"subscription": true},
	})
	if rerr == nil {
		t.Fatalf("SetPatternValidator: expected validation error for unknown pattern")
	}
	if !strings.Contains(rerr.Error(), "azure_armm") {
		t.Fatalf("error should mention the bogus pattern name, got %v", rerr)
	}
}

func TestEngine_PatternRule_LoadError_UnknownComponent(t *testing.T) {
	p := writeRules(t, `
- id: bogus
  match:
    pattern: azure_arm
    components:
      subscripton: SUB-A
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	rerr := e.SetPatternValidator(stubValidator{
		allowedPattern:    "azure_arm",
		allowedComponents: map[string]bool{"subscription": true},
	})
	if rerr == nil {
		t.Fatalf("expected validation error for unknown component")
	}
	if !strings.Contains(rerr.Error(), "subscripton") {
		t.Fatalf("error should mention the typo, got %v", rerr)
	}
}

func TestEngine_NoPatternClause_BehavesAsBefore(t *testing.T) {
	// Sanity: existing rules without pattern: continue to match
	// requests regardless of MatchedPattern.
	p := writeRules(t, `
- id: allow-example
  match:
    host: example.com
  effect: allow
`)
	e, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	r := newReq("example.com", "GET", "/")
	r.MatchedPattern = &types.MatchedPattern{Name: "azure_arm", Components: map[string]string{}}
	if d := e.Decide(r); d.Effect != types.EffectAllow {
		t.Fatalf("non-pattern rule should still match; got %s", d.Effect)
	}
}
