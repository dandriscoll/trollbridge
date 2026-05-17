package policy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// TestEngine_RejectsUnknownRuleKey closes issue #123 for rule files:
// an unknown key on a Rule (here `priorty:`, a typo of `priority:`)
// must fail the load loudly. Before strict decoding the key was
// silently dropped and the rule loaded with the typo'd field ignored.
func TestEngine_RejectsUnknownRuleKey(t *testing.T) {
	p := writeRules(t, `
- id: typo-rule
  match: {host: example.com}
  effect: allow
  priorty: 500
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for unknown rule key `priorty`")
	}
	if !strings.Contains(err.Error(), "priorty") {
		t.Errorf("error should name the offending key `priorty`: %v", err)
	}
}

// TestEngine_RejectsUnknownMatchKey is the security-relevant case
// from #123: a misspelled match sub-key (`math:` for `method:`)
// silently broadens a rule under lenient decoding — the method
// constraint simply vanishes. Strict decoding must reject it.
func TestEngine_RejectsUnknownMatchKey(t *testing.T) {
	p := writeRules(t, `
- id: broadened-rule
  match:
    host: example.com
    math: ["GET"]
  effect: allow
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for unknown match key `math`")
	}
	if !strings.Contains(err.Error(), "math") {
		t.Errorf("error should name the offending key `math`: %v", err)
	}
}

// TestEngine_RejectsToolField closes issue #125: a `tool:` clause
// was parsed into Match.Tool and silently ignored by the evaluator.
// After removal, strict decoding (#123) must reject the clause with
// an error naming `tool` so the operator notices.
func TestEngine_RejectsToolField(t *testing.T) {
	p := writeRules(t, `
- id: tool-clause-rejected
  match:
    host: example.com
    tool: claude-code
  effect: allow
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for unsupported match key `tool`")
	}
	if !strings.Contains(err.Error(), "tool") {
		t.Errorf("error should name the offending key `tool`: %v", err)
	}
}

// TestEngine_RejectsMultipleDocuments closes issue #126 for rule
// files: a `---`-separated second document of rules was silently
// ignored. The reload must reject the file.
func TestEngine_RejectsMultipleDocuments(t *testing.T) {
	p := writeRules(t, `
- id: a
  match: {host: example.com}
  effect: allow
---
- id: b
  match: {host: other.com}
  effect: deny
`)
	_, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err == nil {
		t.Fatal("expected error for multi-document rule file")
	}
	if !strings.Contains(err.Error(), "multiple") {
		t.Errorf("error should mention multiple documents: %v", err)
	}
}

// TestEngine_CommentsOnlyRuleFile guards the io.EOF handling on the
// rule-file side: a comments-only rule file (the shape of the
// gitignored default rules.yaml) must load as zero rules with no
// error, not a bare EOF parse error (#123 regression guard).
func TestEngine_CommentsOnlyRuleFile(t *testing.T) {
	p := writeRules(t, "# structured rules go here\n# none yet\n")
	e, err := NewEngine("default-deny", []string{p}, Phase1KnownModifiers())
	if err != nil {
		t.Fatalf("comments-only rule file must load as zero rules: %v", err)
	}
	if n := len(e.Rules()); n != 0 {
		t.Errorf("comments-only rule file: got %d rules, want 0", n)
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
