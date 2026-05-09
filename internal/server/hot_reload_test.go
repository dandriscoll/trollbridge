package server

import (
	"context"
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

// bootHotReloadProxy boots a Server with WatchAndReload running.
// Returns the proxy address, the allow.txt path, and a cancel.
func bootHotReloadProxy(t *testing.T, allowSeed, denySeed, rules string) (string, string, string, *advisor.MockProvider, context.CancelFunc, chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	denyPath := filepath.Join(dir, "deny.txt")
	rulesPath := filepath.Join(dir, "rules.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(allowPath, []byte(allowSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte(denySeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()

	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 32, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 2, OnTimeout: "deny", MaxPending: 4},
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
	prov := &advisor.MockProvider{Output: advisor.Output{Effect: "deny", Confidence: "high"}}
	srv.SetAdvisorProvider(prov)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.SetLists(linesFrom(allowPath), linesFrom(denyPath)); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		_ = srv.ServeOnListener(ctx, ln)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	return ln.Addr().String(), allowPath, denyPath, prov, cancel, done
}

// linesFrom reads a file and returns its non-empty, non-comment
// lines. Used by hot-reload tests to seed the in-memory lists from
// fixture files (the on-disk format predates v2; the lists API now
// takes []string).
func linesFrom(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// TestHotReload_FileEditTakesEffectWithoutRestart confirmed an
// out-of-band edit to allow.txt was picked up by the watcher in v1.
// v2 stores lists inline in trollbridge.yaml and the only mutation
// path is the REPL (which calls configwrite + SetLists). The
// file-watcher behaviour is gone; this test is skipped.
func TestHotReload_FileEditTakesEffectWithoutRestart(t *testing.T) {
	t.Skip("v2: file-watcher removed; lists mutate via console REPL + configwrite + SetLists")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "post-reload-ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	addr, allowPath, _, _, cancel, done := bootHotReloadProxy(t, "", "", "")
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}

	// Pre-reload: empty list, default-deny → 470 (StatusTrollbridgeDeclined).
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != StatusTrollbridgeDeclined {
		t.Fatalf("pre-reload: status %d, want %d", resp.StatusCode, StatusTrollbridgeDeclined)
	}

	// Edit allow.txt out-of-band. Sleep past mtime granularity.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(allowPath, []byte(originHost+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait up to 4 seconds for the watcher to pick it up.
	deadline := time.Now().Add(4 * time.Second)
	var status int
	for time.Now().Before(deadline) {
		resp, err = c.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		status = resp.StatusCode
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if status == 200 && strings.Contains(string(body), "post-reload-ok") {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("post-reload request did not reach 200; last status=%d", status)
}

// TestAdvisor_ReceivesListsAsInput verifies the advisor sees the
// configured allow + deny lists in its input. Property (5) of the
// brief.
func TestAdvisor_ReceivesListsAsInput(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask
  match: {host: %s}
  effect: ask_llm
`, originHost)

	// Capture the Input the advisor saw.
	var seen advisor.Input
	prov := &captureProvider{output: advisor.Output{Effect: "allow", Confidence: "high"}, captured: &seen}

	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	denyPath := filepath.Join(dir, "deny.txt")
	rulesPath := filepath.Join(dir, "rules.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(allowPath, []byte("allowed-host.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte("denied-host.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()

	cfg := &config.Config{
		Mode:    "default-deny",
		Logging: config.Logging{AuditPath: auditPath, AuditBufferSize: 16, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 2, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "t", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
		LLM:       config.LLM{Enabled: true, ConfidenceFloor: "medium", OnUnavailable: "ask_user", TimeoutSeconds: 5, CacheTTLSeconds: 60},
	}
	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(auditPath, 16, audit.OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, logger)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAdvisorProvider(prov)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.SetLists(linesFrom(allowPath), linesFrom(denyPath)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = srv.ServeOnListener(ctx, ln)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Assert advisor saw both lists.
	if !contains(seen.AllowList, "allowed-host.example") {
		t.Errorf("advisor.Input.AllowList missing seed: %v", seen.AllowList)
	}
	if !contains(seen.DenyList, "denied-host.example") {
		t.Errorf("advisor.Input.DenyList missing seed: %v", seen.DenyList)
	}
}

// TestAdvisor_CannotMutateLists pins the human-only mutation
// property: even when the advisor's response carries a
// `suggested_rule`, neither allow.txt nor deny.txt is modified.
func TestAdvisor_CannotMutateLists(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask
  match: {host: %s}
  effect: ask_llm
`, originHost)

	// Advisor proposes a suggested_rule. trollbridge must NOT
	// auto-apply it.
	prov := &advisor.MockProvider{Output: advisor.Output{
		Effect:        "allow",
		Confidence:    "high",
		Reason:        "would-suggest-adding-host",
		SuggestedRule: map[string]any{"add_to_allow": originHost},
	}}

	allowSeed := "# initial header\npre.example\n"
	denySeed := "pastebin.com\n"
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	denyPath := filepath.Join(dir, "deny.txt")
	rulesPath := filepath.Join(dir, "rules.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(allowPath, []byte(allowSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte(denySeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	allowMTime, _ := os.Stat(allowPath)
	denyMTime, _ := os.Stat(denyPath)

	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()
	cfg := &config.Config{
		Mode:    "default-deny",
		Logging: config.Logging{AuditPath: auditPath, AuditBufferSize: 16, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 2, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "t", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
		LLM:       config.LLM{Enabled: true, ConfidenceFloor: "medium", OnUnavailable: "ask_user", TimeoutSeconds: 5, CacheTTLSeconds: 60},
	}
	engine, _ := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
	logger, _ := audit.New(auditPath, 16, audit.OverflowBlock)
	srv, _ := NewWithAudit(cfg, engine, logger)
	srv.SetAdvisorProvider(prov)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	srv.SetLists(linesFrom(allowPath), linesFrom(denyPath))
	done := make(chan struct{})
	go func() {
		_ = srv.ServeOnListener(ctx, ln)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, _ := c.Get(origin.URL)
	if resp != nil {
		resp.Body.Close()
	}

	// Wait a watcher cycle to be sure no spurious reload happened.
	time.Sleep(1500 * time.Millisecond)

	// Files MUST NOT have been modified.
	a, _ := os.Stat(allowPath)
	d, _ := os.Stat(denyPath)
	if !a.ModTime().Equal(allowMTime.ModTime()) {
		t.Errorf("allow.txt was modified by the advisor flow")
	}
	if !d.ModTime().Equal(denyMTime.ModTime()) {
		t.Errorf("deny.txt was modified by the advisor flow")
	}
	body, _ := os.ReadFile(allowPath)
	if string(body) != allowSeed {
		t.Errorf("allow.txt contents changed:\n%s", string(body))
	}
	body, _ = os.ReadFile(denyPath)
	if string(body) != denySeed {
		t.Errorf("deny.txt contents changed:\n%s", string(body))
	}

	if prov.Calls == 0 {
		t.Error("advisor was not consulted; the test could not exercise the mutation pin")
	}
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

// captureProvider records the Input it received for assertion.
type captureProvider struct {
	output   advisor.Output
	captured *advisor.Input
}

func (c *captureProvider) Classify(ctx context.Context, in advisor.Input) (advisor.Output, error) {
	*c.captured = in
	return c.output, nil
}
