package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/policy"
)

// bootAdvisorProxy boots a Phase 1-style plain-HTTP proxy with the
// LLM advisor enabled and a swappable provider injected.
func bootAdvisorProxy(t *testing.T, rules string, prov advisor.Provider) (*Server, string, string, context.CancelFunc, chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()

	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 32, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
		LLM: config.LLM{
			Enabled: true, ConfidenceFloor: "medium", OnUnavailable: "ask_user",
			TimeoutSeconds: 5, CacheTTLSeconds: 60,
		},
	}
	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(auditPath, 32, audit.OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, logger)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAdvisorProvider(prov)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.ServeOnListener(ctx, ln)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	return srv, ln.Addr().String(), auditPath, cancel, done
}

func TestAdvisor_AllowsViaAskLLMRule(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "advisor-ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask-the-advisor
  match: {host: %s}
  effect: ask_llm
`, originHost)
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect: "allow", Confidence: "high", Reason: "trusted host class",
	}}
	srv, addr, auditPath, cancel, done := bootAdvisorProxy(t, rules, prov)
	defer func() { cancel(); <-done }()
	_ = srv

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "advisor-ok") {
		t.Errorf("status=%d body=%q want 200 'advisor-ok'", resp.StatusCode, string(body))
	}
	if prov.Calls < 1 {
		t.Error("advisor was never called")
	}

	// Audit log: should record advisor as decision_source.
	cancel()
	<-done
	f, _ := os.Open(auditPath)
	defer f.Close()
	sc := bufio.NewScanner(f)
	advFound := false
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
			if e.DecisionSource == "llm_advisor" && e.Decision == "allow" {
				advFound = true
			}
		}
	}
	if !advFound {
		t.Error("expected an llm_advisor / allow audit entry")
	}
}

func TestAdvisor_DeniesViaAskLLMRule(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask-the-advisor
  match: {host: %s}
  effect: ask_llm
`, originHost)
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect: "deny", Confidence: "high", Reason: "looks like exfil",
	}}
	srv, addr, _, cancel, done := bootAdvisorProxy(t, rules, prov)
	defer func() { cancel(); <-done }()
	_ = srv

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}
}

// TestAdvisor_DoesNotElevateAskUser is the non-elevation guard test.
// A rule with effect: ask_user MUST land in the approval queue
// regardless of what the advisor recommends; the advisor isn't
// even consulted.
func TestAdvisor_DoesNotElevateAskUser(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: must-ask-operator
  match: {host: %s}
  effect: ask_user
`, originHost)
	// Advisor would say allow if asked. We expect it NOT to be
	// asked because the rule says ask_user.
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect: "allow", Confidence: "high",
	}}
	// Approval queue with 1-second timeout to deny.
	srv, addr, _, cancel, done := bootAdvisorProxy(t, rules, prov)
	defer func() { cancel(); <-done }()
	_ = srv

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 10 * time.Second}
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := c.Get(origin.URL)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Wait for timeout (5s in cfg) → 403.
	select {
	case resp := <-respCh:
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status: got %d, want 403 after operator timeout", resp.StatusCode)
		}
		resp.Body.Close()
	case err := <-errCh:
		t.Fatalf("client error: %v", err)
	case <-time.After(8 * time.Second):
		t.Fatal("client never resolved (advisor should NOT have elevated to allow)")
	}

	if prov.Calls != 0 {
		t.Errorf("advisor was called %d times; expected 0 (rule is ask_user)", prov.Calls)
	}
}
