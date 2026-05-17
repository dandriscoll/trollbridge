package llmtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// bundle_test.go covers the framework's own logic — bundle loading
// + result comparison — without a live LLM. These tests run on
// every `go test ./...` invocation (no build tag).

func TestLoad_AcceptsValidBundle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "valid.yaml")
	body := `name: smoke
description: smoke test
directives: be helpful
lists:
  allow: [GET https://api.example.com/*]
  deny: []
cases:
  - name: github
    request:
      method: GET
      host: api.github.com
      path: /repos/x/y
    expect:
      verdict: allow
      min_confidence: medium
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Name != "smoke" {
		t.Errorf("name = %q, want %q", b.Name, "smoke")
	}
	if len(b.Cases) != 1 || b.Cases[0].Name != "github" {
		t.Errorf("cases parsed wrong: %+v", b.Cases)
	}
}

func TestLoad_RejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	body := `name: bad
directives: x
cases:
  - name: c1
    request:
      method: GET
      host: x
    expect: {verdict: allow}
typo_at_top: 1
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected Load to reject unknown bundle key")
	}
	if !strings.Contains(err.Error(), "typo_at_top") {
		t.Errorf("error should name the offending key: %v", err)
	}
}

func TestLoad_RejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing-bundle-name",
			body: "directives: x\ncases: [{name: c1, request: {method: GET, host: x}, expect: {verdict: allow}}]\n",
			want: "name",
		},
		{
			name: "missing-cases",
			body: "name: b\ndirectives: x\n",
			want: "case",
		},
		{
			name: "missing-case-name",
			body: "name: b\ndirectives: x\ncases: [{request: {method: GET, host: x}, expect: {verdict: allow}}]\n",
			want: "name",
		},
		{
			name: "missing-method",
			body: "name: b\ndirectives: x\ncases: [{name: c1, request: {host: x}, expect: {verdict: allow}}]\n",
			want: "method",
		},
		{
			name: "missing-host",
			body: "name: b\ndirectives: x\ncases: [{name: c1, request: {method: GET}, expect: {verdict: allow}}]\n",
			want: "host",
		},
		{
			name: "missing-verdict",
			body: "name: b\ndirectives: x\ncases: [{name: c1, request: {method: GET, host: x}, expect: {}}]\n",
			want: "verdict",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.yaml")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.want) {
				t.Errorf("error should mention %q: %v", tt.want, err)
			}
		})
	}
}

// stubProvider returns a fixed Output regardless of Input. Used to
// exercise the runner + checker without a live LLM.
type stubProvider struct {
	out advisor.Output
	err error
}

func (s stubProvider) Classify(ctx context.Context, in advisor.Input) (advisor.Output, error) {
	return s.out, s.err
}

func TestRun_PassesWhenVerdictAndConfidenceMatch(t *testing.T) {
	prov := stubProvider{out: advisor.Output{Effect: "allow", Confidence: "high", Reason: "ok"}}
	b := &Bundle{
		Name:       "t",
		Directives: "x",
		Cases: []Case{{
			Name:    "c1",
			Request: Request{Method: "GET", Host: "api.example.com"},
			Expect:  Expect{Verdict: "allow", MinConfidence: "medium"},
		}},
	}
	results := Run(context.Background(), prov, b)
	if len(results) != 1 || !results[0].Pass {
		t.Errorf("expected one passing result; got %+v", results)
	}
}

func TestRun_FailsOnVerdictMismatch(t *testing.T) {
	prov := stubProvider{out: advisor.Output{Effect: "deny", Confidence: "high"}}
	b := &Bundle{
		Name: "t", Directives: "x",
		Cases: []Case{{
			Name:    "c1",
			Request: Request{Method: "GET", Host: "x"},
			Expect:  Expect{Verdict: "allow"},
		}},
	}
	r := Run(context.Background(), prov, b)
	if r[0].Pass {
		t.Error("expected fail on verdict mismatch")
	}
	if !strings.Contains(r[0].Reason, "verdict mismatch") {
		t.Errorf("reason should name the mismatch: %q", r[0].Reason)
	}
}

func TestRun_FailsOnConfidenceBelowFloor(t *testing.T) {
	prov := stubProvider{out: advisor.Output{Effect: "allow", Confidence: "low"}}
	b := &Bundle{
		Name: "t", Directives: "x",
		Cases: []Case{{
			Name:    "c1",
			Request: Request{Method: "GET", Host: "x"},
			Expect:  Expect{Verdict: "allow", MinConfidence: "medium"},
		}},
	}
	r := Run(context.Background(), prov, b)
	if r[0].Pass {
		t.Error("expected fail on confidence below floor")
	}
	if !strings.Contains(r[0].Reason, "below floor") {
		t.Errorf("reason should name the floor breach: %q", r[0].Reason)
	}
}

func TestRun_FailsOnConfidenceAboveCeiling(t *testing.T) {
	// Bundle wants "ambiguous → at most medium"; LLM returned "high" — assertion fails.
	prov := stubProvider{out: advisor.Output{Effect: "ask_user", Confidence: "high"}}
	b := &Bundle{
		Name: "t", Directives: "x",
		Cases: []Case{{
			Name:    "c1",
			Request: Request{Method: "GET", Host: "x"},
			Expect:  Expect{Verdict: "ask_user", MaxConfidence: "medium"},
		}},
	}
	r := Run(context.Background(), prov, b)
	if r[0].Pass {
		t.Error("expected fail on confidence above ceiling")
	}
}

func TestRun_FailsOnClassifyError(t *testing.T) {
	prov := stubProvider{err: contextlessErr("network unreachable")}
	b := &Bundle{
		Name: "t", Directives: "x",
		Cases: []Case{{
			Name:    "c1",
			Request: Request{Method: "GET", Host: "x"},
			Expect:  Expect{Verdict: "allow"},
		}},
	}
	r := Run(context.Background(), prov, b)
	if r[0].Pass {
		t.Error("expected fail on classify error")
	}
	if !strings.Contains(r[0].Reason, "classify error") {
		t.Errorf("reason should mention the upstream error: %q", r[0].Reason)
	}
}

// contextlessErr is a tiny error type used to drive the runner's
// error path without depending on a stdlib sentinel.
type contextlessErr string

func (e contextlessErr) Error() string { return string(e) }

func TestBuildInput_DefaultsSchemeAndPort(t *testing.T) {
	b := &Bundle{Directives: "d", Lists: BundleLists{Allow: []string{"a"}, Deny: []string{"d"}}}
	c := Case{Request: Request{Method: "GET", Host: "x", Path: "/p"}}
	in := buildInput(b, c)
	if in.Scheme != "https" {
		t.Errorf("scheme = %q, want https (default)", in.Scheme)
	}
	if in.Port != 443 {
		t.Errorf("port = %d, want 443 (https default)", in.Port)
	}
	if in.Directives != "d" {
		t.Error("directives not forwarded")
	}
	if len(in.AllowList) != 1 || len(in.DenyList) != 1 {
		t.Error("lists not forwarded")
	}
}

func TestBuildInput_HTTPSchemeDefaultsPort80(t *testing.T) {
	c := Case{Request: Request{Method: "GET", Host: "x", Scheme: "http"}}
	in := buildInput(&Bundle{}, c)
	if in.Port != 80 {
		t.Errorf("port = %d, want 80 (http default)", in.Port)
	}
}
