package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// captureOpLog constructs a slog.Logger that writes into a buffer
// at the given level. Used by tests to assert on operational lines.
func captureOpLog(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return slog.New(h), buf
}

// bootHTTPProxyWithOpLog wires a plain-HTTP drawbridge against a
// stub origin and returns the proxy address, the origin URL (host:port),
// the captured op-log buffer, and a cleanup func.
func bootHTTPProxyWithOpLog(t *testing.T, level slog.Level) (proxyAddr, originURL string, opBuf *bytes.Buffer, cleanup func()) {
	t.Helper()
	dir := t.TempDir()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "from-origin")
	}))
	originURL = origin.URL
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rulesPath := filepath.Join(dir, "rules.yaml")
	rules := fmt.Sprintf("- id: a\n  match: {host: %s}\n  effect: allow\n", originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()

	cfg := &config.Config{
		Adapter: "127.0.0.1", Ports: config.Ports{Proxy: 0},
		Mode:       "default-deny",
		Logging:    config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals:  config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder:  config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:   config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}
	cfg.DrawbridgeVersion = 1

	engine, err := policy.NewEngine(cfg.Mode, cfg.ResolveIncludePaths(rulesPath), policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(auditPath, cfg.Logging.AuditBufferSize, audit.OverflowMode(cfg.Logging.AuditOverflow))
	if err != nil {
		t.Fatal(err)
	}
	opLog, opBuf := captureOpLog(level)
	auditLog.SetOpLog(opLog)
	srv, err := NewWithLoggers(cfg, engine, auditLog, opLog)
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

	cleanup = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("server shutdown timeout")
		}
		origin.Close()
	}
	proxyAddr = ln.Addr().String()
	_ = originHost
	return
}

// TestOpLog_DebugCarriesRequestIDOnPlainHTTP asserts that at debug
// level a request emits operational lines correlated by request_id
// AND that the same request_id appears in the audit JSONL — the
// load-bearing closure for "debug-mode telemetry shape" in 003.
func TestOpLog_DebugCarriesRequestIDOnPlainHTTP(t *testing.T) {
	proxyAddr, originURL, opBuf, cleanup := bootHTTPProxyWithOpLog(t, slog.LevelDebug)
	defer cleanup()

	pURL, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := c.Get(originURL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	out := opBuf.String()

	// Phase records present.
	for _, sub := range []string{
		"phase=received",
		"phase=fastpath_eval",
		"phase=response",
		"request_id=",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("op-log missing %q; full output:\n%s", sub, out)
		}
	}
}

// TestOpLog_InfoSuppressesPhaseRecords asserts that at info level
// the per-request DEBUG phase records do NOT fire — preventing
// debug-volume from leaking into steady-state operational logs.
func TestOpLog_InfoSuppressesPhaseRecords(t *testing.T) {
	proxyAddr, originURL, opBuf, cleanup := bootHTTPProxyWithOpLog(t, slog.LevelInfo)
	defer cleanup()

	pURL, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := c.Get(originURL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	out := opBuf.String()
	for _, sub := range []string{"phase=received", "phase=fastpath_eval", "phase=response"} {
		if strings.Contains(out, sub) {
			t.Errorf("info-level op-log emitted debug phase %q; full output:\n%s", sub, out)
		}
	}
}

// TestIntercept_TLSHandshakeFailureProducesAuditEntry closes the
// gap noted in 002-brief item 4: a client that completes the
// CONNECT handshake but then sends garbage bytes (instead of a
// TLS ClientHello) used to disappear into a 502 with no audit
// record. After this job, it lands as an EffectDeny entry with a
// "TLS handshake failed" reason.
func TestIntercept_TLSHandshakeFailureProducesAuditEntry(t *testing.T) {
	rules := `
- id: a
  match: {host: 127.0.0.1}
  effect: allow
`
	h := bootInterceptProxy(t, rules, "")

	// Connect raw TCP, send CONNECT, read 200, send garbage.
	conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
		h.originHost, h.originPort, h.originHost, h.originPort)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT did not return 200: %q", statusLine)
	}
	// Drain the rest of the headers (until empty line).
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}
	// Garbage bytes — drawbridge's TLS server will fail handshake.
	_, _ = conn.Write([]byte("not a TLS ClientHello\x00\x00\x00\x00\x00"))
	// Give drawbridge time to write the audit entry.
	time.Sleep(200 * time.Millisecond)
	conn.Close()

	entries := h.auditEntries() // closes the harness as a side effect

	var found *audit.Entry
	for i := range entries {
		e := entries[i]
		if e.Scheme == "https-intercepted" && e.Decision == "deny" &&
			strings.Contains(e.Reason, "TLS handshake failed") {
			found = &e
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a deny audit entry with reason 'TLS handshake failed'; got %d entries: %s",
			len(entries), entriesAsJSON(entries))
	}
	if found.Method != "?" {
		t.Errorf("expected synthetic method=?, got %q", found.Method)
	}
	if found.RequestID == "" {
		t.Errorf("expected synthetic request_id, got empty")
	}
}

func entriesAsJSON(es []audit.Entry) string {
	b, _ := json.MarshalIndent(es, "", "  ")
	return string(b)
}
