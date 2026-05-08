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
	"github.com/dandriscoll/drawbridge/internal/ca"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
)

// interceptHarness wires a drawbridge with interception enabled,
// using a fresh CA and a stub HTTPS origin whose cert is signed by
// a *separate* test CA that drawbridge's originRoots trusts.
type interceptHarness struct {
	t           *testing.T
	srv         *Server
	addr        string
	auditPath   string
	dbCA        *ca.CA
	cancel      context.CancelFunc
	done        chan struct{}
	originHost  string
	originPort  int
	originURL   string
}

func bootInterceptProxy(t *testing.T, rules string, redactionYAML string) *interceptHarness {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	// Generate the drawbridge CA (ECDSA for speed in tests).
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	dbCA, err := ca.Init(caCertPath, caKeyPath, ca.KeyTypeECDSAP256, false)
	if err != nil {
		t.Fatal(err)
	}

	// Origin: httptest.NewTLSServer uses its OWN cert. We trust it
	// in drawbridge's originRoots by adding the test server's
	// CA to the system pool we'll override.
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the inbound body for assertion.
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got: %s", string(body))
	}))
	t.Cleanup(originSrv.Close)
	originURL := originSrv.URL
	uHost := strings.TrimPrefix(originURL, "https://")
	originHost, originPortStr, _ := net.SplitHostPort(uHost)
	originPort := 0
	fmt.Sscanf(originPortStr, "%d", &originPort)

	// Pick free port for the control plane.
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String(); _ = ctrlAddr
	ctrlLn.Close()

	cfg := &config.Config{
		Adapter: "127.0.0.1", Ports: config.Ports{Proxy: 0},
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
			Enabled: true,
			CA: config.CACfg{CertPath: caCertPath, KeyPath: caKeyPath},
			LeafKeyType: "ecdsa-p256",
			LeafCertTTLHours: 24,
		},
	}
	if redactionYAML != "" {
		// Parse the redaction block as YAML and graft it onto cfg.
		var wrapper struct {
			Redaction config.Redaction `yaml:"redaction"`
		}
		// trivial: load from a temp file via config.Load to reuse
		// the parser. Build a minimal config file.
		mainCfgPath := filepath.Join(dir, "drawbridge.yaml")
		_ = ctrlAddr
		if err := os.WriteFile(mainCfgPath, []byte(`drawbridge_version: 2
adapter: lo
ports: {proxy: 0, control: 0}
mode: default-deny
interception:
  enabled: true
  ca:
    cert_path: `+caCertPath+`
    key_path: `+caKeyPath+`
  leaf_key_type: ecdsa-p256
logging:
  audit_path: `+auditPath+`
identities:
  - id: test-client
    match: {source_ip: 127.0.0.1}
policy:
  include: [`+rulesPath+`]
`+redactionYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := config.Load(mainCfgPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Redaction = loaded.Redaction
		_ = wrapper
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
	// Add the test origin's CA to drawbridge's originRoots so
	// drawbridge can verify it on dial-out.
	originCert := originSrv.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(originCert)
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
	return &interceptHarness{
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
}

func (h *interceptHarness) close() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("intercept harness shutdown timeout")
	}
}

// clientWithOurCA returns an http.Client that uses the proxy AND
// trusts drawbridge's CA (so the client doesn't reject the
// intercepted leaf).
func (h *interceptHarness) clientWithOurCA() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(h.dbCA.Cert)
	pURL, _ := url.Parse("http://" + h.addr)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
				// httptest origin's cert CN is "127.0.0.1" so we
				// also let the client use that as ServerName.
			},
		},
		Timeout: 10 * time.Second,
	}
}

func (h *interceptHarness) auditEntries() []audit.Entry {
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
		if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
			out = append(out, e)
		}
	}
	return out
}

func TestIntercept_AllowsAndForwardsThroughTLS(t *testing.T) {
	rules := `
- id: a
  match: {host: 127.0.0.1}
  effect: allow
`
	h := bootInterceptProxy(t, rules, "")
	defer h.close()

	c := h.clientWithOurCA()
	resp, err := c.Post(h.originURL+"/path", "text/plain", bytes.NewReader([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "got: hello") {
		t.Errorf("body: got %q", string(body))
	}

	entries := h.auditEntries()
	httpsIntercepted := false
	for _, e := range entries {
		if e.Scheme == "https-intercepted" && e.Decision == "allow" && e.Path == "/path" {
			httpsIntercepted = true
		}
	}
	if !httpsIntercepted {
		t.Error("expected an https-intercepted audit entry with path=/path")
	}
}

func TestIntercept_DeniesPathAndAuditsCleanly(t *testing.T) {
	rules := `
- id: deny-secret-path
  priority: 500
  match:
    host: 127.0.0.1
    path: /secret
  effect: deny

- id: allow-other
  priority: 100
  match:
    host: 127.0.0.1
  effect: allow
`
	h := bootInterceptProxy(t, rules, "")
	defer h.close()

	c := h.clientWithOurCA()
	resp, err := c.Get(h.originURL + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403; body=%s", resp.StatusCode, string(body))
	}
	if reason := resp.Header.Get("Drawbridge-Reason"); reason == "" {
		t.Error("missing Drawbridge-Reason header on intercepted deny")
	}

	entries := h.auditEntries()
	denyFound := false
	for _, e := range entries {
		if e.Scheme == "https-intercepted" && e.Decision == "deny" && e.Path == "/secret" && e.RuleID == "deny-secret-path" {
			denyFound = true
		}
	}
	if !denyFound {
		t.Error("expected an https-intercepted deny audit entry for /secret")
	}
}

// TestIntercept_BodyRedactionSweep is the "no plaintext secrets in
// audit log" sweep test required by DESIGN.md §19.3.
func TestIntercept_BodyRedactionSweep(t *testing.T) {
	rules := `
- id: a
  match: {host: 127.0.0.1}
  effect: allow
`
	redactionYAML := `redaction:
  default_modifiers: [redact_authorization_header, redact_cookie]
  body_redactors:
    - regex: "secret-XYZ"
    - jsonpath: $.password
    - regex: "(?i)bearer [a-z0-9._-]+"
`
	h := bootInterceptProxy(t, rules, redactionYAML)
	defer h.close()

	c := h.clientWithOurCA()
	// JSON body with a sensitive field.
	jsonBody := []byte(`{"username":"alice","password":"hunter2"}`)
	req, _ := http.NewRequest("POST", h.originURL+"/login", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-XYZ-token-abc.def")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Force flush.
	h.cancel()
	<-h.done

	data, err := os.ReadFile(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("hunter2")) {
		t.Errorf("audit log leaked password 'hunter2'")
	}
	if bytes.Contains(data, []byte("secret-XYZ-token-abc.def")) {
		t.Errorf("audit log leaked bearer token")
	}
	if bytes.Contains(data, []byte("Bearer secret-XYZ")) {
		t.Errorf("audit log contains bearer prefix + secret")
	}
	if !bytes.Contains(data, []byte("<redacted>")) {
		t.Errorf("audit log missing <redacted> marker; full audit:\n%s", string(data))
	}
}

// Body cap fail-closed regression (carry-forward 032.I.4).
func TestEngine_FailsClosedOnBodyRequiredButMissing(t *testing.T) {
	rules := `
- id: deny-secret-bodies
  priority: 500
  match:
    host: 127.0.0.1
    method: POST
    body_pattern: "(?i)secret"
  effect: deny

- id: allow-other
  priority: 100
  match: {host: 127.0.0.1}
  effect: allow
`
	h := bootInterceptProxy(t, rules, "")
	defer h.close()

	// We need an over-cap body. But our test config has the
	// default 1MB cap. Set Server.MaxBodySampleBytes to a small
	// value first.
	h.srv.MaxBodySampleBytes = 16

	c := h.clientWithOurCA()
	// Body LARGER than the cap — body_pattern can't sample it.
	// "deny-secret-bodies" should still deny via fail-closed.
	bigBody := bytes.Repeat([]byte("A"), 1000) // no "secret" — but rule says it would have required body.
	resp, err := c.Post(h.originURL+"/x", "application/octet-stream", bytes.NewReader(bigBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403 (fail-closed on body-required rule)", resp.StatusCode)
	}
}
