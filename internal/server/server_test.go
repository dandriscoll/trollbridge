package server

import (
	"bufio"
	"context"
	"crypto/tls"
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

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/policy"
)

// proxyHarness boots a real trollbridge server on a random port,
// returns a client wired to use it as proxy, and a function to
// stop everything.
type proxyHarness struct {
	t        *testing.T
	srv      *Server
	addr     string
	auditPath string
	cancel   context.CancelFunc
	done     chan struct{}
}

func bootProxy(t *testing.T, mode string, rules string) *proxyHarness {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	cfg := &config.Config{
		Proxy: config.Bind{Host: "127.0.0.1", Port: 0},
		Mode:      mode,
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 60, OnTimeout: "deny", MaxPending: 16},
		Forwarder: config.Forwarder{MaxIdleConns: 16, MaxIdleConnsPerHost: 4, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{
			{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}},
		},
		Policy: config.Policy{Include: []string{rulesPath}},
	}

	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}

	auditLogger, err := audit.New(auditPath, cfg.Logging.AuditBufferSize, audit.OverflowMode(cfg.Logging.AuditOverflow))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, auditLogger)
	if err != nil {
		t.Fatal(err)
	}

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
	return &proxyHarness{
		t: t, srv: srv, addr: ln.Addr().String(),
		auditPath: auditPath, cancel: cancel, done: done,
	}
}

func (h *proxyHarness) close() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("proxy shutdown timed out")
	}
}

func (h *proxyHarness) clientThroughProxy() *http.Client {
	pURL, _ := url.Parse("http://" + h.addr)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}
}

// auditEntries returns all parsed audit entries written to disk.
// Closes the audit logger first to flush.
func (h *proxyHarness) auditEntries() []audit.Entry {
	h.cancel()
	<-h.done
	f, err := os.Open(h.auditPath)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			h.t.Fatalf("bad audit JSON: %v: %s", err, sc.Text())
		}
		out = append(out, e)
	}
	return out
}

// stub origin for plain-HTTP tests.
func plainOrigin(t *testing.T, body string) (*httptest.Server, string) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Echo-Method", r.Method)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

func TestProxy_AllowsHTTPMatchingRule(t *testing.T) {
	origin, originURL := plainOrigin(t, "hello-from-origin")
	originHost := strings.TrimPrefix(originURL, "http://")
	originHostOnly, _, _ := net.SplitHostPort(originHost)

	rules := fmt.Sprintf(`
- id: allow-origin
  match:
    host: %s
  effect: allow
`, originHostOnly)
	h := bootProxy(t, "default-deny", rules)
	defer h.close()

	c := h.clientThroughProxy()
	resp, err := c.Get(origin.URL + "/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-origin" {
		t.Errorf("body: got %q", string(body))
	}

	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries written")
	}
	last := entries[len(entries)-1]
	if last.Decision != "allow" {
		t.Errorf("audit decision: got %s, want allow", last.Decision)
	}
	if last.RuleID != "allow-origin" {
		t.Errorf("audit rule_id: got %s, want allow-origin", last.RuleID)
	}
	if last.RuleSetVersion == "" {
		t.Error("audit rule_set_version empty")
	}
	if last.IdentityID != "test-client" {
		t.Errorf("audit identity_id: got %s, want test-client", last.IdentityID)
	}
}

func TestProxy_DeniesUnmatchedHTTPInDefaultDeny(t *testing.T) {
	_, originURL := plainOrigin(t, "shouldnotreach")
	h := bootProxy(t, "default-deny", `
- id: nothing
  match: {host: "never.match.example"}
  effect: allow
`)
	defer h.close()

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}
	if reason := resp.Header.Get("Trollbridge-Reason"); reason == "" {
		t.Error("missing Trollbridge-Reason header")
	}

	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	last := entries[len(entries)-1]
	if last.Decision != "deny" {
		t.Errorf("audit decision: got %s, want deny", last.Decision)
	}
	if last.DecisionSource != "default" {
		t.Errorf("audit decision_source: got %s, want default", last.DecisionSource)
	}
}

func TestProxy_RejectsExplicitDenyRule(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))

	rules := fmt.Sprintf(`
- id: deny-origin
  match: {host: %s}
  effect: deny
`, originHostOnly)
	h := bootProxy(t, "default-allow", rules)
	defer h.close()

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}

	entries := h.auditEntries()
	last := entries[len(entries)-1]
	if last.Decision != "deny" || last.RuleID != "deny-origin" {
		t.Errorf("audit: got decision=%s rule=%s", last.Decision, last.RuleID)
	}
	if last.DecisionSource != "rule" {
		t.Errorf("audit decision_source: got %s, want rule", last.DecisionSource)
	}
}

func TestProxy_AuditEntryHasRequiredFields(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))

	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHostOnly)
	h := bootProxy(t, "default-deny", rules)
	defer h.close()

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	e := entries[len(entries)-1]
	required := map[string]string{
		"timestamp":      e.Timestamp,
		"request_id":     e.RequestID,
		"session_id":     e.SessionID,
		"identity_id":    e.IdentityID,
		"client_addr":    e.ClientAddr,
		"method":         e.Method,
		"scheme":         e.Scheme,
		"host":           e.Host,
		"decision":       e.Decision,
		"decision_source": e.DecisionSource,
		"rule_set_version": e.RuleSetVersion,
		"reason": e.Reason,
	}
	for k, v := range required {
		if v == "" {
			t.Errorf("audit field %s is empty", k)
		}
	}
	if e.AuditSchemaVersion == 0 {
		t.Error("audit_schema_version not set")
	}
}

// CONNECT tunneling integration test.
func TestProxy_ConnectAllowed_TunnelsBytes(t *testing.T) {
	// Stub TLS origin.
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-ok")
	}))
	defer tlsOrigin.Close()
	originHost := strings.TrimPrefix(tlsOrigin.URL, "https://")
	originHostOnly, _, _ := net.SplitHostPort(originHost)

	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHostOnly)
	h := bootProxy(t, "default-deny", rules)
	defer h.close()

	c := h.clientThroughProxy()
	resp, err := c.Get(tlsOrigin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tls-ok" {
		t.Errorf("body: got %q", string(body))
	}

	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	// Find the CONNECT entry.
	found := false
	for _, e := range entries {
		if e.Method == "CONNECT" {
			found = true
			if e.Decision != "allow" {
				t.Errorf("CONNECT decision: got %s, want allow", e.Decision)
			}
			if e.Scheme != "https-tunneled" {
				t.Errorf("scheme: got %s, want https-tunneled", e.Scheme)
			}
		}
	}
	if !found {
		t.Error("no CONNECT audit entry")
	}
}

func TestProxy_ConnectDenied(t *testing.T) {
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsOrigin.Close()

	h := bootProxy(t, "default-deny", `
- id: nothing
  match: {host: never.match.example}
  effect: allow
`)
	defer h.close()

	c := h.clientThroughProxy()
	_, err := c.Get(tlsOrigin.URL)
	if err == nil {
		t.Fatal("expected client error on denied CONNECT")
	}

	entries := h.auditEntries()
	found := false
	for _, e := range entries {
		if e.Method == "CONNECT" && e.Decision == "deny" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a CONNECT deny audit entry")
	}
}

func TestProxy_RuleReload_VersionChanges(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	v1 := fmt.Sprintf(`
- id: deny-it
  match: {host: %s}
  effect: deny
`, originHostOnly)
	if err := os.WriteFile(rulesPath, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 16, AuditOverflow: "block"},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}
	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.Phase1KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(auditPath, 16, audit.OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, auditLog)
	if err != nil {
		t.Fatal(err)
	}
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
	defer func() {
		cancel()
		<-done
	}()

	v1ver := engine.RuleSetVersion()

	// Rewrite to allow.
	v2 := fmt.Sprintf(`
- id: allow-it
  match: {host: %s}
  effect: allow
`, originHostOnly)
	if err := os.WriteFile(rulesPath, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err != nil {
		t.Fatal(err)
	}
	v2ver := engine.RuleSetVersion()
	if v1ver == v2ver {
		t.Errorf("rule_set_version did not change after reload")
	}

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("after reload: status %d, want 200", resp.StatusCode)
	}
}
