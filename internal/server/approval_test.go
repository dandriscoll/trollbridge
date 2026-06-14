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

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/policy"
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
		Approvals: config.Approvals{TimeoutSeconds: timeoutSec, OnTimeout: onTimeout, MaxPending: 16},
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
	t.Cleanup(func() { _ = auditLog.Close() })
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

// listPending uses the in-process Queue API directly. (v2's control
// plane is mTLS-only; cert plumbing is exercised by control_test.go.
// These tests focus on hold-flow correctness, not the wire path.)
func (h *approvalHarness) listPending() []map[string]any {
	snaps := h.srv.Queue().Pending()
	out := make([]map[string]any, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, map[string]any{
			"id":          s.ID,
			"identity_id": s.IdentityID,
			"host":        s.Host,
			"port":        s.Port,
			"path":        s.Path,
		})
	}
	return out
}

func (h *approvalHarness) approve(id, scope string) {
	if !h.srv.Queue().Approve(id, scope, "test") {
		h.t.Fatalf("approve %s: hold not found", id)
	}
}

func (h *approvalHarness) deny(id, reason string) {
	h.srv.Queue().Deny(id, reason, "test")
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
		if resp.StatusCode != StatusTrollbridgeDeclined {
			t.Errorf("status: got %d, want %d", resp.StatusCode, StatusTrollbridgeDeclined)
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
	if resp.StatusCode != StatusTrollbridgeDeclined {
		t.Errorf("status: got %d, want %d after timeout", resp.StatusCode, StatusTrollbridgeDeclined)
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
	// At least one session should be visible (read in-process; the
	// HTTP path is exercised in control_test.go).
	if h.srv.SessionsTracker() == nil {
		t.Skip("session tracker not exposed by harness")
	}
	if len(h.srv.SessionsTracker().Snapshot()) == 0 {
		t.Error("expected at least one session")
	}
}

// TestApproval_ClientDisconnectFreesSlot pins #208 at the wire level:
// a held proxied request whose client disconnects (request-context
// canceled) must release its waiter and free the max_pending slot
// PROMPTLY — not after timeout_seconds. Uses a long timeout so only the
// disconnect can free the hold.
func TestApproval_ClientDisconnectFreesSlot(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask-the-operator
  match: {host: %s}
  effect: ask_user
`, originHostOnly)
	h := bootApprovalProxy(t, rules, 30, "deny") // 30s timeout: only disconnect frees it
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()

	// Wait for the hold to occupy a slot.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(h.listPending()) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(h.listPending()) != 1 {
		t.Fatalf("hold never appeared; Pending=%d", len(h.listPending()))
	}

	// Client disconnects.
	cancel()

	// The slot must free promptly — well under the 30s timeout.
	freed := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.listPending()) == 0 {
			freed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !freed {
		t.Fatalf("max_pending slot not freed after client disconnect (waiter pinned to timeout); Pending=%d", len(h.listPending()))
	}
	<-errCh // the canceled request returns an error; drain it
}

// TestOpenMode_AllowsAllTrafficAndBypassesQueue pins #209 at the wire
// level: while the open window is active, a request that policy would
// hold (ask_user) is instead ALLOWED — forwarded to the origin, audited
// with decision_source=open_mode, and never enqueued as a hold (the
// queue/lists are bypassed). Closing the window reverts to holding.
func TestOpenMode_AllowsAllTrafficAndBypassesQueue(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin-ok")
	}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: ask-the-operator
  match: {host: %s}
  effect: ask_user
`, originHostOnly)
	h := bootApprovalProxy(t, rules, 30, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 10 * time.Second}

	// Open the window: the ask_user request must now be allowed.
	h.srv.ExtendOpenMode()
	if active, _ := h.srv.OpenModeState(); !active {
		t.Fatal("open mode not active after ExtendOpenMode")
	}

	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatalf("request under open mode: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "origin-ok" {
		t.Fatalf("open mode should allow+forward: status=%d body=%q", resp.StatusCode, string(body))
	}
	// Open mode bypasses the queue entirely — no hold created.
	if n := len(h.listPending()); n != 0 {
		t.Errorf("open mode created %d hold(s); it must bypass the queue", n)
	}
	// Audit records the bypass as open_mode.
	if !auditHasDecisionSource(t, h.auditPath, "open_mode", 2*time.Second) {
		t.Errorf("no audit entry with decision_source=open_mode")
	}

	// Close: the same request reverts to being held.
	h.srv.CloseOpenMode()
	if active, _ := h.srv.OpenModeState(); active {
		t.Fatal("open mode still active after CloseOpenMode")
	}
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()
	heldAgain := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.listPending()) == 1 {
			heldAgain = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !heldAgain {
		t.Errorf("after close, the request should be held again (open mode did not revert)")
	}
	// Resolve the dangling hold so the test goroutine returns cleanly.
	for _, hp := range h.listPending() {
		h.deny(hp["id"].(string), "test cleanup")
	}
	<-errCh
}

// auditHasDecisionSource polls the audit log for an entry carrying the
// given decision_source within the deadline.
func auditHasDecisionSource(t *testing.T, auditPath, source string, within time.Duration) bool {
	t.Helper()
	want := `"decision_source":"` + source + `"`
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(auditPath); err == nil && strings.Contains(string(data), want) {
			return true
		}
		time.Sleep(40 * time.Millisecond)
	}
	return false
}
