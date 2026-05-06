package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
)

// TestConnect_AuditEntryLandsEvenOnImmediateShutdown is the
// regression test filed in 031.I.3.
func TestConnect_AuditEntryLandsEvenOnImmediateShutdown(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-ok")
	}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHostOnly)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pick free port for control plane.
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String()
	ctrlLn.Close()

	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 16, AuditOverflow: "block"},
		Approvals: config.Approvals{ControlListen: ctrlAddr, TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
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

	// Open a CONNECT through the proxy.
	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Trigger immediate shutdown.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}

	// Audit log must contain a CONNECT entry.
	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	connectFound := false
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
			if e.Method == "CONNECT" && e.Decision == "allow" {
				connectFound = true
			}
		}
	}
	if !connectFound {
		t.Error("CONNECT audit entry was not flushed during shutdown")
	}
}
