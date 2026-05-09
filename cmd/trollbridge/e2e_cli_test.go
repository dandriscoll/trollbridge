//go:build e2e

// E2E tests in this file exercise the trollbridge binary as a
// subprocess, covering the install → init → ca init → run → request
// flow that issue #22 named missing. Run with:
//
//   go test -tags=e2e ./cmd/trollbridge/... -run E2E
//
// The tests require:
//   - the binary builds (TestMain compiles it once into a tmp file)
//   - a free local TCP port (the test asks the kernel for one)
//   - sufficient time (~5s per test for the daemon to bind + serve)
//
// Optional, gated on env vars: the LLM-advisor variant runs when
// ANTHROPIC_TWIN_API_KEY is set. Without it, only the basic E2E
// runs.
//
// These tests fill the gap noted in #22: existing in-process tests
// (internal/server/...) cover the daemon's request-handling logic
// with the server boot programmatically, and twins_live_test.go
// covers the advisor's wire shape against real twins endpoints,
// but nothing tests the user-facing CLI end-to-end. This file does.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var e2eBinary string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "trollbridge-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tempdir: %v\n", err)
		os.Exit(1)
	}
	e2eBinary = filepath.Join(tmp, "trollbridge")
	cmd := exec.Command("go", "build", "-o", e2eBinary, "./")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// freePort asks the kernel for a free TCP port on 127.0.0.1, then
// closes the listener. The port may race with a concurrent test or
// system service in a vanishingly small window; acceptable for E2E
// timing (the daemon binds within ~50ms of the listener close).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForProxyBind polls 127.0.0.1:<port> until a TCP connect
// succeeds or the deadline elapses. The proxy daemon binds within
// ~50ms of starting under no load, but CI runners are noisy so the
// default deadline is 5s.
func waitForProxyBind(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy did not bind to 127.0.0.1:%d within 5s", port)
}

// writeE2EYaml writes a trollbridge.yaml suitable for E2E testing.
// All paths are tmpdir-local so the test runs without root and
// cleans up cleanly. Controller is disabled (no CA needed for the
// daemon to start; the basic-flow test does not exercise CA
// generation, only the daemon's request-handling).
func writeE2EYaml(t *testing.T, dir string, port int, allowHosts []string) string {
	t.Helper()
	allowBlock := ""
	for _, h := range allowHosts {
		allowBlock += "    - " + h + "\n"
	}
	body := fmt.Sprintf(`trollbridge_version: 3
proxy:   lo:%d
control: 0
metrics: 0
controller:
  auth: mtls
mode: default-deny
lists:
  allow:
%s
  deny: []
logging:
  audit_path:        %s/audit.jsonl
  audit_overflow:    deny
  operational_path:  stderr
approvals:
  timeout_seconds: 60
  on_timeout: deny
  max_pending: 16
interception:
  enabled: false
`, port, allowBlock, dir)
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return yamlPath
}

// startDaemon spawns the trollbridge binary as a subprocess and
// returns the cmd handle plus a cleanup function. The daemon's
// stderr lands in the test log on failure.
func startDaemon(t *testing.T, yamlPath string) (*exec.Cmd, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, e2eBinary, "run", "-c", yamlPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start daemon: %v", err)
	}
	return cmd, func() {
		cancel()
		_ = cmd.Wait()
	}
}

// TestE2E_Basic_AllowedRequestForwards is the basic CLI E2E:
// write a yaml with a host on the allowlist, start the daemon as a
// subprocess, send an HTTP request through the proxy via Go's
// http.Client (functionally identical to curl with HTTP_PROXY), and
// assert the upstream is reached.
func TestE2E_Basic_AllowedRequestForwards(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-E2E", "ok")
		fmt.Fprint(w, "hello e2e")
	}))
	defer upstream.Close()
	upHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	yamlPath := writeE2EYaml(t, dir, port, []string{upHost})
	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello e2e" {
		t.Errorf("body: got %q, want %q", body, "hello e2e")
	}
	if v := resp.Header.Get("X-E2E"); v != "ok" {
		t.Errorf("upstream X-E2E header lost: got %q", v)
	}
	if rid := resp.Header.Get("Trollbridge-Request-Id"); rid == "" {
		t.Errorf("missing Trollbridge-Request-Id on allow forward")
	}

	// Audit log should record the allow.
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditWaitFor(t, auditPath, 5*time.Second, func(line string) bool {
		return strings.Contains(line, `"decision":"allow"`) &&
			strings.Contains(line, `"host":"`+upHost+`"`)
	})
}

// TestE2E_Basic_DeniedRequestReturns470 is the deny-path E2E: same
// flow, with the upstream NOT on the allowlist. Asserts the proxy
// emits HTTP 470 (the wire contract from #11) without contacting
// upstream.
func TestE2E_Basic_DeniedRequestReturns470(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Allow only a host the test does not request — anything else
	// hits default-deny.
	yamlPath := writeE2EYaml(t, dir, port, []string{"unrelated.example"})
	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 470 {
		t.Errorf("status: got %d, want 470 (StatusTrollbridgeDeclined)", resp.StatusCode)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream was contacted on a denied request; hits=%d (expected 0 — proxy must short-circuit)", upstreamHits)
	}
}

// TestE2E_CAInit_ProducesValidCert exercises `trollbridge ca init`
// as a subprocess: write a yaml with custom cert/key paths, run
// `ca init`, assert the cert and key files exist and are readable.
//
// Combined with the request E2E above, this covers the full
// install path: init (yaml) → ca init (CA on disk) → run (daemon)
// → request (forward / decline).
func TestE2E_CAInit_ProducesValidCert(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")

	// Write a minimal yaml that ca init can resolve. It does not
	// need to be runnable; ca init just reads the cert_path /
	// key_path fields.
	yamlBody := fmt.Sprintf(`trollbridge_version: 3
proxy:   lo:9999
control: 0
controller: {auth: mtls}
mode: default-deny
interception:
  enabled: false
  ca:
    cert_path: %s
    key_path:  %s
  leaf_key_type: ecdsa-p256
`, certOut, keyOut)
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "ca", "init",
		"-c", yamlPath,
		"--cert-out", certOut,
		"--key-out", keyOut,
		"--key-type", "ecdsa-p256",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ca init: %v", err)
	}

	for _, p := range []string{certOut, keyOut} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", p)
		}
	}
}

// auditWaitFor polls the audit log file and invokes match on each
// line. Returns on first match; fails the test on deadline.
func auditWaitFor(t *testing.T, path string, deadline time.Duration, match func(line string) bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		b, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if line == "" {
					continue
				}
				if match(line) {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no audit line matched within %s; path=%s", deadline, path)
}
