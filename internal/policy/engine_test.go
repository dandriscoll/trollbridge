package policy

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// rules helper writes a YAML rule file into a temp dir and returns
// the path.
func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newReq(host, method, path string) *types.RequestEvent {
	r := &types.RequestEvent{
		Host:    host,
		Method:  method,
		Path:    path,
		Port:    443,
		Headers: http.Header{},
		IdentityID: "test-id",
	}
	return r
}

func TestEngine_DefaultDeny(t *testing.T) {
	e, err := NewEngine("default-deny", nil, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decide(newReq("example.com", "GET", "/"))
	if d.Effect != types.EffectDeny {
		t.Fatalf("default-deny: expected deny, got %s", d.Effect)
	}
	if d.Source != types.SourceDefault {
		t.Fatalf("source: expected default, got %s", d.Source)
	}
}

func TestEngine_DefaultAllow(t *testing.T) {
	e, _ := NewEngine("default-allow", nil, Phase1KnownModifiers())
	d := e.Decide(newReq("example.com", "GET", "/"))
	if d.Effect != types.EffectAllow {
		t.Fatalf("default-allow: expected allow, got %s", d.Effect)
	}
}

func TestEngine_DefaultAskFallsToAskUserPhase1(t *testing.T) {
	e, _ := NewEngine("default-ask", nil, Phase1KnownModifiers())
	d := e.Decide(newReq("example.com", "GET", "/"))
	if d.Effect != types.EffectAskUser {
		t.Fatalf("default-ask: expected ask_user, got %s", d.Effect)
	}
}

func TestEngine_HostMatch(t *testing.T) {
	p := writeRules(t, `
- id: allow-example
  match:
    host: example.com
  effect: allow
`)
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host string
		want types.Effect
	}{
		{"example.com", types.EffectAllow},
		{"other.com", types.EffectDeny},
	}
	for _, c := range cases {
		d := e.Decide(newReq(c.host, "GET", "/"))
		if d.Effect != c.want {
			t.Errorf("host=%s: got %s, want %s", c.host, d.Effect, c.want)
		}
	}
}

func TestEngine_WildcardHost(t *testing.T) {
	p := writeRules(t, `
- id: allow-subs
  match:
    host: "*.example.com"
  effect: allow
`)
	e, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	cases := []struct {
		host string
		want types.Effect
	}{
		{"a.example.com", types.EffectAllow},
		{"a.b.example.com", types.EffectAllow},
		{"example.com", types.EffectDeny}, // bare domain not covered by *.example.com
		{"badexample.com", types.EffectDeny},
	}
	for _, c := range cases {
		d := e.Decide(newReq(c.host, "GET", "/"))
		if d.Effect != c.want {
			t.Errorf("host=%s: got %s, want %s", c.host, d.Effect, c.want)
		}
	}
}

func TestEngine_MethodList(t *testing.T) {
	p := writeRules(t, `
- id: allow-reads
  match:
    host: api.example.com
    method: ["GET", "HEAD"]
  effect: allow
`)
	e, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	for _, m := range []string{"GET", "HEAD", "get"} { // method match is case-insensitive
		if d := e.Decide(newReq("api.example.com", m, "/")); d.Effect != types.EffectAllow {
			t.Errorf("method=%s: got %s, want allow", m, d.Effect)
		}
	}
	for _, m := range []string{"POST", "DELETE"} {
		if d := e.Decide(newReq("api.example.com", m, "/")); d.Effect != types.EffectDeny {
			t.Errorf("method=%s: got %s, want deny", m, d.Effect)
		}
	}
}

func TestEngine_Identity(t *testing.T) {
	p := writeRules(t, `
- id: allow-coding-agent
  match:
    host: api.example.com
    identity: coding-agent
  effect: allow
`)
	e, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	r := newReq("api.example.com", "GET", "/")
	r.IdentityID = "coding-agent"
	if d := e.Decide(r); d.Effect != types.EffectAllow {
		t.Errorf("matched identity: got %s, want allow", d.Effect)
	}
	r.IdentityID = "other"
	if d := e.Decide(r); d.Effect != types.EffectDeny {
		t.Errorf("non-matching identity: got %s, want deny", d.Effect)
	}
}

func TestEngine_Priority_FirstHigherPriorityWins(t *testing.T) {
	p := writeRules(t, `
- id: low-allow
  priority: 50
  match:
    host: example.com
  effect: allow
- id: high-deny
  priority: 500
  match:
    host: example.com
  effect: deny
`)
	e, _ := NewEngine("default-allow", []string{p}, Phase1KnownModifiers())
	d := e.Decide(newReq("example.com", "GET", "/"))
	if d.Effect != types.EffectDeny || d.RuleID != "high-deny" {
		t.Errorf("expected deny by high-deny, got %s by %s", d.Effect, d.RuleID)
	}
}

func TestEngine_RejectsMissingEffect(t *testing.T) {
	p := writeRules(t, `
- id: bad
  match: {host: example.com}
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for missing effect")
	}
}

func TestEngine_RejectsUnknownModifier(t *testing.T) {
	p := writeRules(t, `
- id: bad
  match: {host: example.com}
  effect: allow
  modifiers: [redact_authrization_header] # typo
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for unknown modifier")
	}
}

func TestEngine_RuleSetVersionStable(t *testing.T) {
	p := writeRules(t, `
- id: a
  match: {host: example.com}
  effect: allow
`)
	e1, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	e2, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if e1.RuleSetVersion() != e2.RuleSetVersion() {
		t.Errorf("expected stable version: %s vs %s", e1.RuleSetVersion(), e2.RuleSetVersion())
	}
}

func TestEngine_Reload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	if err := os.WriteFile(p, []byte(`
- id: deny-all
  match: {host: example.com}
  effect: deny
`), 0o600); err != nil {
		t.Fatal(err)
	}
	e, _ := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	v1 := e.RuleSetVersion()
	if d := e.Decide(newReq("example.com", "GET", "/")); d.Effect != types.EffectDeny {
		t.Fatal("v1 expected deny")
	}

	if err := os.WriteFile(p, []byte(`
- id: allow-all
  match: {host: example.com}
  effect: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if e.RuleSetVersion() == v1 {
		t.Errorf("version did not change on reload")
	}
	if d := e.Decide(newReq("example.com", "GET", "/")); d.Effect != types.EffectAllow {
		t.Errorf("v2 expected allow, got %s", d.Effect)
	}
}

// TestEngine_SetMode_AffectsNoRuleMatchPath closes #111 (mode hot-
// reload). Switching mode at runtime changes the no-rule-match
// fallback decision without re-parsing rules or re-constructing
// the engine.
func TestEngine_SetMode_AffectsNoRuleMatchPath(t *testing.T) {
	e, err := NewEngine("default-deny", nil, Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	if d := e.Decide(testReq()); d.Effect != types.EffectDeny {
		t.Errorf("default-deny: got %s, want deny", d.Effect)
	}
	e.SetMode("default-allow")
	if got := e.Mode(); got != "default-allow" {
		t.Errorf("Mode() = %q, want default-allow", got)
	}
	if d := e.Decide(testReq()); d.Effect != types.EffectAllow {
		t.Errorf("after SetMode(default-allow): got %s, want allow", d.Effect)
	}
	e.SetMode("default-ask")
	if d := e.Decide(testReq()); d.Effect != types.EffectAskUser {
		t.Errorf("after SetMode(default-ask): got %s, want ask_user", d.Effect)
	}
}

func testReq() *types.RequestEvent {
	return &types.RequestEvent{
		ID:     "test-req-1",
		Method: "GET",
		Scheme: "https",
		Host:   "example.com",
		Port:   443,
		Path:   "/",
	}
}
