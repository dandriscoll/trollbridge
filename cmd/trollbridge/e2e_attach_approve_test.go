//go:build e2e

// E2E test: operator approval over the mTLS control plane.
//
// Closes #96. The attach binary's mTLS handshake is covered at the
// unit layer (cmd/trollbridge/attach_test.go) and the wire layer
// (internal/control/control_test.go) but not transitively at the
// real-binary subprocess level. Attach is the operator's remote
// interaction surface; this test catches cross-component regressions
// that the lower-layer suites cannot.
//
// Steps (matching the issue body):
//   1. ca init writes a CA on disk into a tempdir.
//   2. trollbridge ca client-cert operator mints the operator's cert.
//   3. Start the daemon with controller.auth=mtls and a known control port.
//   4. Submit a request through the proxy that goes into ask_user.
//   5. Make a mTLS HTTPS POST to /v1/holds/<id>/approve using the operator cert.
//   6. Assert the original request resumes and forwards to upstream.
//
// Run with:
//
//	go test -tags=e2e ./cmd/trollbridge/... -run TestE2E_AttachApprove

package main

import (
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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestE2E_AttachApprove(t *testing.T) {
	dir := t.TempDir()
	proxyPort := freePort(t)
	controlPort := freePort(t)
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	operatorCertPath := filepath.Join(dir, "operator.crt")
	operatorKeyPath := filepath.Join(dir, "operator.key")

	// Upstream that records hits — must be reached exactly once after
	// the operator approves the held request.
	var upMu sync.Mutex
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upMu.Lock()
		upstreamHits++
		upMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()
	upHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	auditPath := filepath.Join(dir, "audit.jsonl")

	// YAML: default-ask + ask_user rule + mTLS controller bound on a
	// known port. signal_after_seconds:0 keeps the consumer blocked
	// until the operator decides; timeout_seconds:30 leaves ample
	// slack for the operator approve round-trip on a noisy CI host.
	// mode: default-ask → any unmatched request lands in ask_user,
	// is enqueued, and blocks for the operator. No advisor or rule
	// file required (the engine's default-ask path produces
	// EffectAskUser directly).
	yamlBody := fmt.Sprintf(`proxy:   lo:%d
control: lo:%d
metrics: 0
controller:
  auth: mtls
mode: default-ask
lists:
  allow: []
  deny: []
logging:
  audit_path:        %s
  audit_overflow:    deny
  operational_path:  stderr
approvals:
  timeout_seconds: 30
  on_timeout: deny
  max_pending: 16
  signal_after_seconds: 0
interception:
  enabled: false
  ca:
    cert_path: %s
    key_path:  %s
`, proxyPort, controlPort, auditPath, caCertPath, caKeyPath)
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step 1: ca init writes the CA on disk.
	caInit := exec.Command(e2eBinary, "ca", "init",
		"-c", yamlPath,
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--key-type", "ecdsa-p256",
	)
	caInit.Stdout = os.Stderr
	caInit.Stderr = os.Stderr
	if err := caInit.Run(); err != nil {
		t.Fatalf("ca init: %v", err)
	}

	// Step 2: mint operator client cert.
	clientCert := exec.Command(e2eBinary, "ca", "client-cert", "operator",
		"-c", yamlPath,
		"--cert-out", operatorCertPath,
		"--key-out", operatorKeyPath,
	)
	clientCert.Stdout = os.Stderr
	clientCert.Stderr = os.Stderr
	if err := clientCert.Run(); err != nil {
		t.Fatalf("ca client-cert: %v", err)
	}

	// Step 3: start the daemon.
	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, proxyPort)
	waitForProxyBind(t, controlPort)

	// Step 4: kick off the proxied request in a goroutine; it blocks
	// until the operator decides. Channel carries the response or the
	// error so the main test body can await both the hold-list poll
	// and the eventual response.
	type proxiedResult struct {
		status int
		body   string
		err    error
	}
	respCh := make(chan proxiedResult, 1)
	go func() {
		proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
			Timeout:   30 * time.Second,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			respCh <- proxiedResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		respCh <- proxiedResult{status: resp.StatusCode, body: string(body)}
	}()

	// mTLS HTTP client for the control plane: load operator
	// cert/key + add the trollbridge CA cert to the trust roots
	// so we accept the controller's server cert.
	mtlsClient := newOperatorMTLSClient(t, caCertPath, operatorCertPath, operatorKeyPath)

	// Step 4 (continued): poll /v1/holds until the held request shows up.
	controlAddr := fmt.Sprintf("127.0.0.1:%d", controlPort)
	var holdID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		hresp, err := mtlsClient.Get("https://" + controlAddr + "/v1/holds")
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if hresp.StatusCode != 200 {
			b, _ := io.ReadAll(hresp.Body)
			hresp.Body.Close()
			t.Fatalf("/v1/holds: status=%d body=%s", hresp.StatusCode, b)
		}
		// Pending() returns []QueuedItem JSON-marshaled — read enough
		// to find the hold id field. Avoid coupling to the exact
		// internal schema by parsing as []map[string]any and looking
		// for the "id" key.
		var pending []map[string]any
		if err := json.NewDecoder(hresp.Body).Decode(&pending); err != nil {
			hresp.Body.Close()
			t.Fatalf("/v1/holds decode: %v", err)
		}
		hresp.Body.Close()
		if len(pending) > 0 {
			if id, ok := pending[0]["id"].(string); ok && id != "" {
				holdID = id
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if holdID == "" {
		t.Fatal("no hold appeared in /v1/holds within 10s — did the proxy enqueue?")
	}

	// Step 5: POST the approve over mTLS.
	approveBody := strings.NewReader(`{"scope":"once"}`)
	approveResp, err := mtlsClient.Post(
		"https://"+controlAddr+"/v1/holds/"+holdID+"/approve",
		"application/json",
		approveBody,
	)
	if err != nil {
		t.Fatalf("approve POST: %v", err)
	}
	approveBytes, _ := io.ReadAll(approveResp.Body)
	approveResp.Body.Close()
	if approveResp.StatusCode != 200 {
		t.Fatalf("approve POST: status=%d body=%s", approveResp.StatusCode, approveBytes)
	}

	// Step 6: the held proxied request must now resume and return the
	// upstream's 200.
	select {
	case got := <-respCh:
		if got.err != nil {
			t.Fatalf("proxied request errored after approve: %v", got.err)
		}
		if got.status != 200 {
			t.Errorf("proxied response status: got %d, want 200 (post-approve resume)", got.status)
		}
		if !strings.Contains(got.body, "upstream-ok") {
			t.Errorf("proxied response body: got %q, want substring %q", got.body, "upstream-ok")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("proxied request did not resume within 15s after operator approve")
	}

	upMu.Lock()
	uh := upstreamHits
	upMu.Unlock()
	if uh != 1 {
		t.Errorf("upstream hit count: got %d, want 1 (approve must forward exactly once)", uh)
	}

	// Audit must record the eventual operator-approved decision.
	auditWaitFor(t, auditPath, 5*time.Second, func(line string) bool {
		return strings.Contains(line, `"decision":"ask_user_resolved_allow"`) &&
			strings.Contains(line, `"decision_source":"approval_queue"`) &&
			strings.Contains(line, `"host":"`+upHost+`"`) &&
			strings.Contains(line, `"response_status":200`)
	})
}

// newOperatorMTLSClient builds an https.Client configured to dial the
// trollbridge control plane: the trollbridge CA cert is added to the
// client's RootCAs (so the controller's server cert verifies), and
// the operator client cert is presented for mTLS.
func newOperatorMTLSClient(t *testing.T, caCertPath, operatorCertPath, operatorKeyPath string) *http.Client {
	t.Helper()
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read ca cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		t.Fatalf("ca cert at %s did not parse as PEM", caCertPath)
	}
	clientCert, err := tls.LoadX509KeyPair(operatorCertPath, operatorKeyPath)
	if err != nil {
		t.Fatalf("load operator cert/key: %v", err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      roots,
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}
