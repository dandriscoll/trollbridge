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
	if resp.StatusCode != StatusTrollbridgeDeclined {
		t.Errorf("status: got %d, want %d", resp.StatusCode, StatusTrollbridgeDeclined)
	}
}

// TestAdvisor_AskUserNowConsultsAdvisor pins the #53 contract: when
// an ask_user rule fires AND an advisor is configured, the advisor
// IS consulted (in parallel with the human approval queue). A
// confident advisor verdict resolves the hold without operator
// action. Pre-#53 the advisor was gated to ask_llm rules only and
// ask_user requests bypassed the LLM entirely.
func TestAdvisor_AskUserNowConsultsAdvisor(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: must-ask-operator
  match: {host: %s}
  effect: ask_user
`, originHost)
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect: "allow", Confidence: "high",
	}}
	srv, addr, _, cancel, done := bootAdvisorProxy(t, rules, prov)
	defer func() { cancel(); <-done }()
	_ = srv

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 10 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200 (advisor confidently allowed)", resp.StatusCode)
	}
	if prov.Calls != 1 {
		t.Errorf("advisor was called %d times; expected 1 (#53: ask_user now consults advisor)", prov.Calls)
	}
}

// TestAdvisor_AskUserUnconfidentFallsToOperator pins the other half
// of #53: when the advisor is unconfident (or returns ask_user), the
// hold remains for the operator. The configured timeout fires and
// the request is denied.
func TestAdvisor_AskUserUnconfidentFallsToOperator(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: must-ask-operator
  match: {host: %s}
  effect: ask_user
`, originHost)
	// Advisor returns low confidence — should NOT auto-resolve.
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect: "allow", Confidence: "low",
	}}
	srv, addr, _, cancel, done := bootAdvisorProxy(t, rules, prov)
	defer func() { cancel(); <-done }()
	_ = srv

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 10 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != StatusTrollbridgeDeclined {
		t.Errorf("status: got %d, want %d (operator timeout after advisor unconfident)",
			resp.StatusCode, StatusTrollbridgeDeclined)
	}
	if prov.Calls != 1 {
		t.Errorf("advisor was called %d times; expected 1 (consulted but unconfident)", prov.Calls)
	}
}
