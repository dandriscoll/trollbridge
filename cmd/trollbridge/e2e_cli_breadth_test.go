//go:build e2e

// E2E breadth tests — extend the happy-path coverage of e2e_cli_test.go
// to the cross-component flows the directive (job 122) named as gaps.
// Run with:
//
//   go test -tags=e2e ./cmd/trollbridge/... -run 'E2E_(Advisor|DefaultAsk)'
//
// Shares the TestMain build-cache with e2e_cli_test.go.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestE2E_AdvisorRoutedDeny exercises the LLM-advisor cross-component
// flow end-to-end: the daemon's advisor reaches a (mock) LLM endpoint
// over real HTTP, the LLM returns a "deny" classification, the proxy
// short-circuits to 470 and records `decision_source: "llm_advisor"`
// in the audit log.
//
// Closes scenario S-083 in 003a-scope-definition.md.
func TestE2E_AdvisorRoutedDeny(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	// Mock LLM endpoint: any request gets a deny verdict. The wire
	// shape mirrors what advisor expects from an anthropic-style
	// provider; the daemon's translator normalizes the response.
	llmCalls := 0
	var llmMu sync.Mutex
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmMu.Lock()
		llmCalls++
		llmMu.Unlock()
		// Minimal anthropic-shaped response: stop reason + content
		// JSON the daemon's translator can parse as `effect: deny`.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "msg-test-1",
			"type":        "message",
			"role":        "assistant",
			"model":       "test-model",
			"stop_reason": "end_turn",
			"content": []map[string]any{
				{"type": "text", "text": `{"effect":"deny","confidence":"high","reason":"test-advisor-deny"}`},
			},
		})
	}))
	defer llm.Close()

	// Upstream that should never be reached on deny.
	upstreamHits := 0
	var upMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upMu.Lock()
		upstreamHits++
		upMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	// Stash a dummy API key so the advisor's APIKeyPath read
	// succeeds. The mock LLM ignores the bearer; trollbridge only
	// requires the file to be readable.
	keyPath := filepath.Join(dir, "llm.key")
	if err := os.WriteFile(keyPath, []byte("test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")

	// A real rule file driven through the supported policy.include
	// surface. One catch-all ask_llm rule routes every request to the
	// LLM advisor. Combined with mode: default-deny below, this rule
	// is the ONLY path to the advisor — delete it and the request is
	// denied by the mode default (decision_source: default, not
	// llm_advisor), which the audit assertion at the end of this test
	// catches. That load-bearing-ness is the point: an earlier version
	// of this test embedded an inline `policy: rules:` block, which
	// config.Policy does not support, so it was silently dropped and
	// the test passed via the default-ask fall-through instead of via
	// a rule (closes #121).
	rulesBody := `- id: route-via-advisor
  description: Route every request to the LLM advisor.
  priority: 10
  match: {}
  effect: ask_llm
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(rulesBody), 0o600); err != nil {
		t.Fatal(err)
	}

	yamlBody := fmt.Sprintf(`proxy:   lo:%d
control: 0
metrics: 0
controller:
  auth: mtls
mode: default-deny
lists:
  allow: []
  deny: []
policy:
  include:
    - rules.yaml
logging:
  audit_path:        %s
  audit_overflow:    deny
  operational_path:  stderr
approvals:
  timeout_seconds: 3
  on_timeout: deny
  max_pending: 16
llm:
  enabled: true
  provider: anthropic
  endpoint: %s
  api_key_path: %s
  model: test-model
  timeout_seconds: 5
  on_unavailable: deny
interception:
  enabled: false
`, port, auditPath, llm.URL, keyPath)
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   8 * time.Second,
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 470 {
		t.Errorf("status: got %d, want 470 (advisor-routed deny short-circuit)", resp.StatusCode)
	}
	upMu.Lock()
	uh := upstreamHits
	upMu.Unlock()
	if uh != 0 {
		t.Errorf("upstream was contacted; hits=%d (expected 0 — advisor-deny must short-circuit)", uh)
	}
	llmMu.Lock()
	lc := llmCalls
	llmMu.Unlock()
	if lc == 0 {
		t.Errorf("LLM endpoint was not consulted; calls=0 (expected >=1)")
	}

	// Audit log must record decision_source=llm_advisor on the
	// denied request. This is the cross-component contract: the
	// advisor reached the LLM, the translator parsed the verdict,
	// the engine resolved to deny, and the audit logger recorded
	// the source. Triangulates against the ask-case telemetry
	// completeness memory pin (122 §F memory references).
	auditWaitFor(t, auditPath, 5*time.Second, func(line string) bool {
		return strings.Contains(line, `"decision":"deny"`) &&
			strings.Contains(line, `"decision_source":"llm_advisor"`) &&
			strings.Contains(line, `"host":"`+upHost+`"`)
	})
}

// TestE2E_DefaultAskHoldTimeoutDeny exercises the held-request state
// machine with signal_after_seconds disabled: mode=default-ask with no
// rule + no list → engine.ask_user → held; timeout_seconds elapses →
// on_timeout=deny → consumer sees 470 + audit records
// decision_source=approval_timeout.
//
// Closes scenario S-082 in 003a-scope-definition.md. The signal_after
// variant (471 wire signal at signal_after_seconds while keeping the
// hold open) is already covered by
// internal/server/signal_after_subprocess_test.go; the gap this test
// closes is the post-timeout audit-source contract on the no-signal
// path.
//
// Tied to the closed-issue lineage #11 (470/471 codes) and #35 (https
// hold timeout in test).
func TestE2E_DefaultAskHoldTimeoutDeny(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	upstreamHits := 0
	var upMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upMu.Lock()
		upstreamHits++
		upMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	auditPath := filepath.Join(dir, "audit.jsonl")
	// signal_after_seconds: 0 (disabled) — the consumer blocks for the
	// full timeout_seconds. Keeps the test single-response and lets us
	// assert on the eventual audit-source.
	yamlBody := fmt.Sprintf(`proxy:   lo:%d
control: 0
metrics: 0
controller:
  auth: mtls
mode: default-ask
lists:
  allow: []
  deny: []
logging:
  audit_path:        %s
  audit_overflow:    deny
  operational_path:  stderr
approvals:
  timeout_seconds: 2
  on_timeout: deny
  max_pending: 16
  signal_after_seconds: 0
interception:
  enabled: false
`, port, auditPath)
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		// Generous client timeout — the proxy holds for ~2s before
		// the on_timeout=deny path resolves and writes the response.
		Timeout: 8 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL, nil)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	// The held request resolves to deny via on_timeout. The wire
	// response is 470 (trollbridge-declined) — the same shape as
	// any other deny.
	if resp.StatusCode != 470 {
		t.Errorf("status: got %d, want 470 (timeout → on_timeout=deny)", resp.StatusCode)
	}
	// Sanity on elapsed: must be at least timeout_seconds (~2s) but
	// not pathologically longer. CI noise budget: 500ms lower-bound
	// slack, 4s upper-bound.
	if elapsed < 1500*time.Millisecond {
		t.Errorf("response returned too early: %v elapsed (want >= ~1.5s — the timeout is 2s)", elapsed)
	}
	if elapsed > 4*time.Second {
		t.Errorf("response returned too late: %v elapsed", elapsed)
	}

	upMu.Lock()
	uh := upstreamHits
	upMu.Unlock()
	if uh != 0 {
		t.Errorf("upstream was contacted while request was held; hits=%d (expected 0)", uh)
	}

	// Audit: the engine's effect token on the timeout path is
	// `ask_user_timed_out` (types.EffectAskUserTimedOut). The
	// decision_source MUST be `approval_timeout`
	// (types.SourceApprovalTimeout) — the wire contract for "the
	// hold timed out without an operator decision". The response
	// status (already checked above) is 470, but the audit record
	// reports the engine-level decision, not the wire-level status.
	auditWaitFor(t, auditPath, 5*time.Second, func(line string) bool {
		return strings.Contains(line, `"decision":"ask_user_timed_out"`) &&
			strings.Contains(line, `"decision_source":"approval_timeout"`) &&
			strings.Contains(line, `"host":"`+upHost+`"`) &&
			strings.Contains(line, `"response_status":470`)
	})
}

// (TestE2E_AttachApprove — full attach → control-plane mTLS → approve
// flow — is deferred for a follow-up job. Setting up the CA + mTLS
// client cert as part of a subprocess E2E test materially expands
// scope beyond this job's proportionality budget; the in-process
// control-plane wire is already covered by internal/control/control_test.go
// and the attach client-side is covered by cmd/trollbridge/attach_test.go.
// See 003f-gap-reconciliation.md and 007-issues.md for the disposition.)

// import suppressor to avoid an unused-import error if a helper above
// is removed during maintenance.
var _ = exec.Command