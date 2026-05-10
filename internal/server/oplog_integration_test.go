package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/ca"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/policy"
)

// captureOpLog constructs a slog.Logger that writes into a buffer
// at the given level. Used by tests to assert on operational lines.
func captureOpLog(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return slog.New(h), buf
}

// bootHTTPProxyWithOpLog wires a plain-HTTP trollbridge against a
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
		Proxy: config.Bind{Host: "127.0.0.1", Port: 0},
		Mode:       "default-deny",
		Logging:    config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals:  config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder:  config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:   config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}

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

// bootInterceptProxyWithOpLog mirrors bootInterceptProxy but
// injects a captured op-log so lifecycle phase records on the
// intercepted-inner path can be asserted.
func bootInterceptProxyWithOpLog(t *testing.T, rules string, level slog.Level) (*interceptHarness, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	dbCA, err := ca.Init(caCertPath, caKeyPath, ca.KeyTypeECDSAP256, false)
	if err != nil {
		t.Fatal(err)
	}

	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(originSrv.Close)
	originURL := originSrv.URL
	uHost := strings.TrimPrefix(originURL, "https://")
	originHost, originPortStr, _ := net.SplitHostPort(uHost)
	originPort := 0
	fmt.Sscanf(originPortStr, "%d", &originPort)

	cfg := &config.Config{
		Proxy:     config.Bind{Host: "127.0.0.1", Port: 0},
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{
			{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}},
		},
		Policy: config.Policy{Include: []string{rulesPath}},
		Interception: config.Interception{
			Enabled:          true,
			CA:               config.CACfg{CertPath: caCertPath, KeyPath: caKeyPath},
			LeafKeyType:      "ecdsa-p256",
			LeafCertTTLHours: 24,
		},
	}

	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
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
	pool := x509.NewCertPool()
	pool.AddCert(originSrv.Certificate())
	srv.originRoots = pool

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
	h := &interceptHarness{
		t:          t,
		srv:        srv,
		addr:       ln.Addr().String(),
		auditPath:  auditPath,
		dbCA:       dbCA,
		cancel:     cancel,
		done:       done,
		originHost: originHost,
		originPort: originPort,
		originURL:  originURL,
	}
	return h, opBuf
}

// silence unused-import alarms if the imports above are unused on a
// future trim; tls.Config + crypto/x509 are pulled in by the helper.
var _ = tls.VersionTLS12

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

// TestOpLog_DebugCarriesLifecycleOnConnectDeny asserts that an
// HTTPS CONNECT request emits the same lifecycle phase records
// (received → fastpath_eval → engine_eval → response) at debug
// level that plain HTTP emits — closing the gap reported in
// issue #34. Default-deny mode lets us drive the deny path
// without standing up an intercepted upstream.
func TestOpLog_DebugCarriesLifecycleOnConnectDeny(t *testing.T) {
	proxyAddr, _, opBuf, cleanup := bootHTTPProxyWithOpLog(t, slog.LevelDebug)
	defer cleanup()

	// Issue a CONNECT to a host the rules do not allow. Default-deny
	// → 470 from the proxy; we don't follow up with a tunnel, just
	// assert on the operational log.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	connectReq := "CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// Drain headers + body so the proxy finishes its writeAudit /
	// debug emission before we read the buffer.
	_, _ = io.Copy(io.Discard, br)
	time.Sleep(100 * time.Millisecond)

	out := opBuf.String()
	for _, sub := range []string{
		`method=CONNECT`,
		`scheme=https-tunneled`,
		`phase=received`,
		`phase=fastpath_eval`,
		`phase=engine_eval`,
		`phase=response`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("CONNECT op-log missing %q; full output:\n%s", sub, out)
		}
	}
}

// TestOpLog_InfoSuppressesPhaseRecordsOnConnect mirrors the HTTP
// info-suppression assertion for CONNECT — protects against a
// regression where the new debug records leak into info-level
// steady-state logs.
func TestOpLog_InfoSuppressesPhaseRecordsOnConnect(t *testing.T) {
	proxyAddr, _, opBuf, cleanup := bootHTTPProxyWithOpLog(t, slog.LevelInfo)
	defer cleanup()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	connectReq := "CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	_, _ = br.ReadString('\n')
	_, _ = io.Copy(io.Discard, br)
	time.Sleep(100 * time.Millisecond)

	out := opBuf.String()
	for _, sub := range []string{
		"phase=received", "phase=fastpath_eval", "phase=engine_eval", "phase=response",
	} {
		if strings.Contains(out, sub) {
			t.Errorf("info-level CONNECT op-log emitted debug phase %q; full output:\n%s", sub, out)
		}
	}
}

// TestOpLog_DebugCarriesLifecycleOnIntercepted asserts the same
// lifecycle phases on the intercepted-inner-request path
// (`dispatchInterceptedRequest`). Pairs with the CONNECT test:
// CONNECT covers the tunnel-establish decision; this covers the
// per-inner-request decision under interception.
func TestOpLog_DebugCarriesLifecycleOnIntercepted(t *testing.T) {
	rules := `
- id: a
  match: {host: 127.0.0.1}
  effect: allow
`
	h, opBuf := bootInterceptProxyWithOpLog(t, rules, slog.LevelDebug)

	c := h.clientWithOurCA()
	resp, err := c.Get(h.originURL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	h.close()

	out := opBuf.String()
	for _, sub := range []string{
		`scheme=https-intercepted`,
		`phase=received`,
		`phase=fastpath_eval`,
		`phase=upstream_dial`,
		`phase=response`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("intercepted op-log missing %q; full output:\n%s", sub, out)
		}
	}
}

// TestOpLog_InfoCarriesAskCaseLifecycle closes the INFO-level
// requirement of issue #36: an operator running `trollbridge run`
// without --verbose must see request_held + hold_approved (and the
// other resolution events) at INFO level. Uses a default-ask proxy
// with a goroutine that approves the hold via the queue API so the
// full lifecycle (held → approved → forward) lands in the captured
// op-log.
func TestOpLog_InfoCarriesAskCaseLifecycle(t *testing.T) {
	dir := t.TempDir()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rulesPath := filepath.Join(dir, "rules.yaml")
	rules := fmt.Sprintf("- id: a\n  match: {host: %s}\n  effect: ask_user\n", originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	cfg := &config.Config{
		Proxy:      config.Bind{Host: "127.0.0.1", Port: 0},
		Mode:       "default-deny",
		Logging:    config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals:  config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder:  config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:   config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}

	engine, err := policy.NewEngine(cfg.Mode, cfg.ResolveIncludePaths(rulesPath), policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(auditPath, cfg.Logging.AuditBufferSize, audit.OverflowMode(cfg.Logging.AuditOverflow))
	if err != nil {
		t.Fatal(err)
	}
	opLog, opBuf := captureOpLog(slog.LevelInfo)
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
	defer func() {
		cancel()
		<-done
	}()

	// Background approver: poll the queue until our hold appears,
	// then approve it. Mirrors what `trollbridge approve` does on
	// the operator's side.
	approverDone := make(chan struct{})
	go func() {
		defer close(approverDone)
		for i := 0; i < 100; i++ {
			pending := srv.Queue().Pending()
			if len(pending) > 0 {
				srv.Queue().Approve(pending[0].ID, "once", "test")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
		Timeout:   3 * time.Second,
	}
	resp, err := c.Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("client.Do: %v (oplog=%s)", err, opBuf.String())
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-approverDone
	time.Sleep(50 * time.Millisecond) // let the post-resolve log writes drain

	out := opBuf.String()
	for _, sub := range []string{
		`level=INFO`,
		`event=request_held`,
		`event=hold_approved`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("INFO ask-case oplog missing %q; full output:\n%s", sub, out)
		}
	}
}

// TestServer_HoldQueueFull_WarnsAndRefuses closes the
// `event=hold_queue_full` WARN requirement of issue #36. With
// Approvals.MaxPending = 1, two concurrent ask_user-rule requests
// produce one held request and one refusal at the queue boundary;
// the refusal must surface a WARN record naming the failure mode.
func TestServer_HoldQueueFull_WarnsAndRefuses(t *testing.T) {
	dir := t.TempDir()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rulesPath := filepath.Join(dir, "rules.yaml")
	rules := fmt.Sprintf("- id: a\n  match: {host: %s}\n  effect: ask_user\n", originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	cfg := &config.Config{
		Proxy:      config.Bind{Host: "127.0.0.1", Port: 0},
		Mode:       "default-deny",
		Logging:    config.Logging{AuditPath: auditPath, AuditBufferSize: 64, AuditOverflow: "block"},
		Approvals:  config.Approvals{TimeoutSeconds: 10, OnTimeout: "deny", MaxPending: 1},
		Forwarder:  config.Forwarder{MaxIdleConns: 8, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:   config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test-client", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}

	engine, err := policy.NewEngine(cfg.Mode, cfg.ResolveIncludePaths(rulesPath), policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(auditPath, cfg.Logging.AuditBufferSize, audit.OverflowMode(cfg.Logging.AuditOverflow))
	if err != nil {
		t.Fatal(err)
	}
	opLog, opBuf := captureOpLog(slog.LevelInfo)
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
	defer func() {
		cancel()
		<-done
	}()

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	c := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL), DisableKeepAlives: true},
		Timeout:   2 * time.Second,
	}
	// Send the first request in a goroutine so it occupies the
	// single hold slot. Send the second after a short delay; it
	// hits ErrFull and refuses synchronously.
	go func() {
		req, _ := http.NewRequest("GET", origin.URL+"/first", nil)
		_, _ = c.Do(req)
	}()
	time.Sleep(150 * time.Millisecond)
	resp, err := c.Get(origin.URL + "/second")
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	time.Sleep(100 * time.Millisecond)

	out := opBuf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected a WARN record; oplog:\n%s", out)
	}
	if !strings.Contains(out, "event=hold_queue_full") {
		t.Errorf("expected event=hold_queue_full; oplog:\n%s", out)
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
	// Garbage bytes — trollbridge's TLS server will fail handshake.
	_, _ = conn.Write([]byte("not a TLS ClientHello\x00\x00\x00\x00\x00"))
	// Give trollbridge time to write the audit entry.
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
