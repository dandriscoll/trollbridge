package server

import (
	"bytes"
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

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
)

type approvalHarness struct {
	t          *testing.T
	srv        *Server
	addr       string
	controlAddr string
	auditPath  string
	cancel     context.CancelFunc
	done       chan struct{}
}

func bootApprovalProxy(t *testing.T, rules string, timeoutSec int, onTimeout string) *approvalHarness {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	// Pick a free port for the control plane.
	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctrlAddr := ctrlLn.Addr().String()
	ctrlLn.Close()

	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals: config.Approvals{ControlListen: ctrlAddr, TimeoutSeconds: timeoutSec, OnTimeout: onTimeout, MaxPending: 16},
		Forwarder: config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{
			{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}},
		},
		Policy: config.Policy{Include: []string{rulesPath}},
	}
	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(auditPath, cfg.Logging.AuditBufferSize, audit.OverflowMode(cfg.Logging.AuditOverflow))
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
	// Give the control plane a moment to bind.
	time.Sleep(50 * time.Millisecond)
	return &approvalHarness{
		t:          t,
		srv:        srv,
		addr:       ln.Addr().String(),
		controlAddr: ctrlAddr,
		auditPath:  auditPath,
		cancel:     cancel,
		done:       done,
	}
}

func (h *approvalHarness) close() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("approval harness shutdown timeout")
	}
}

// listPending hits the control API.
func (h *approvalHarness) listPending() []map[string]any {
	resp, err := http.Get("http://" + h.controlAddr + "/v1/holds")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *approvalHarness) approve(id, scope string) {
	body, _ := json.Marshal(map[string]string{"scope": scope})
	resp, err := http.Post(
		"http://"+h.controlAddr+"/v1/holds/"+id+"/approve",
		"application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("approve: %s: %s", resp.Status, string(b))
	}
}

func (h *approvalHarness) deny(id, reason string) {
	body, _ := json.Marshal(map[string]string{"reason": reason})
	resp, err := http.Post(
		"http://"+h.controlAddr+"/v1/holds/"+id+"/deny",
		"application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
}

func TestApproval_ApprovedRequestUnblocks(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "approved-body")
	}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask-the-operator
  match: {host: %s}
  effect: ask_user
`, originHostOnly)
	h := bootApprovalProxy(t, rules, 5, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
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

	// Wait for the hold to appear.
	deadline := time.Now().Add(2 * time.Second)
	var holdID string
	for time.Now().Before(deadline) {
		holds := h.listPending()
		if len(holds) > 0 {
			holdID = holds[0]["id"].(string)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if holdID == "" {
		t.Fatal("no hold appeared on the control API")
	}

	h.approve(holdID, "once")

	select {
	case resp := <-respCh:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "approved-body" {
			t.Errorf("body: got %q", string(body))
		}
	case err := <-errCh:
		t.Fatalf("client got error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not unblock after approval")
	}
}

func TestApproval_DeniedRequestRefused(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask
  match: {host: %s}
  effect: ask_user
`, originHostOnly)
	h := bootApprovalProxy(t, rules, 5, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
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

	deadline := time.Now().Add(2 * time.Second)
	var holdID string
	for time.Now().Before(deadline) {
		holds := h.listPending()
		if len(holds) > 0 {
			holdID = holds[0]["id"].(string)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if holdID == "" {
		t.Fatal("no hold appeared on the control API")
	}

	h.deny(holdID, "operator-test-deny")

	select {
	case resp := <-respCh:
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status: got %d, want 403", resp.StatusCode)
		}
		resp.Body.Close()
	case err := <-errCh:
		t.Fatalf("client got error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not finish after deny")
	}
}

func TestApproval_TimesOut(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask
  match: {host: %s}
  effect: ask_user
`, originHostOnly)
	// 1 second timeout; default deny.
	h := bootApprovalProxy(t, rules, 1, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403 after timeout", resp.StatusCode)
	}
}

func TestSessions_TrackedAcrossRequests(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHostOnly)
	h := bootApprovalProxy(t, rules, 5, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := c.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// At least one session should be visible.
	resp, err := http.Get("http://" + h.controlAddr + "/v1/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sessions []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) == 0 {
		t.Error("expected at least one session")
	}
}
