//go:build !windows

package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/ca"
)

// TestSubprocess_InterceptStreamingBodyDisconnectFreesSlot is the #213
// subprocess deliverable: drive the REAL run binary, intercept a CONNECT
// tunnel, hold the inner request whose body is OVER the sample cap (the
// streaming case), disconnect the client mid-hold, and assert the held
// slot frees promptly via oplog `event=hold_abandoned` — well under
// timeout_seconds. The abandoned event's `scheme=https-intercepted`
// proves the intercept path (not the outer CONNECT) was the held one
// (insight §37).
//
// Before #213, an over-sample-cap held body took the no-watcher fallback
// and the slot stayed pinned to timeout_seconds; the fix drains the
// framed body into memory before the hold so the disconnect watcher runs
// uniformly. The origin is never dialed (the request is held then
// abandoned), so this test needs only the client↔proxy CA, not origin
// trust.
func TestSubprocess_InterceptStreamingBodyDisconnectFreesSlot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("subprocess test relies on POSIX signals")
	}
	repoRoot := findRepoRoot(t)
	binPath := filepath.Join(t.TempDir(), "trollbridge")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/trollbridge")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, string(out))
	}

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rulesPath := filepath.Join(dir, "rules.yaml")
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	// Generate the trollbridge CA (ECDSA for test speed); the client
	// trusts it so it accepts the intercepted leaf.
	dbCA, err := ca.Init(caCertPath, caKeyPath, ca.KeyTypeECDSAP256, false)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}

	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	// A dummy TCP origin the proxy can DIAL when establishing the
	// CONNECT tunnel (handleConnect dials the origin before it decides
	// to intercept; it closes that conn and terminates TLS locally). The
	// origin never has to speak TLS or serve anything: the held inner
	// request is abandoned, never forwarded. It just needs to accept the
	// dial so the CONNECT succeeds and interception proceeds.
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer originLn.Close()
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	originHost, originPort, _ := net.SplitHostPort(originLn.Addr().String())

	// Allow the CONNECT to the origin, hold only the inner POST /held.
	rules := fmt.Sprintf(`
- id: ask-held
  match: {host: %s, path: /held}
  effect: ask_user
- id: allow-connect
  match: {host: %s}
  effect: allow
`, originHost, originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	// timeout_seconds generously long so ONLY the disconnect can free
	// the slot within the (much shorter) assertion window.
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-deny
interception:
  enabled: true
  ca:
    cert_path: %s
    key_path: %s
  leaf_key_type: ecdsa-p256
logging:
  audit_path: %s
approvals:
  timeout_seconds: 30
identities:
  - id: test-client
    match: {source_ip: 127.0.0.1}
policy:
  include: [%s]
`, proxyPort, caCertPath, caKeyPath, auditPath, rulesPath)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancelCtx := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelCtx()
	cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath, "--no-console")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	var mu sync.Mutex
	cmd.Stderr = &lockedWriter{w: &stderr, mu: &mu}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	stderrContains := func(s string) bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(stderr.String(), s)
	}
	waitFor := func(s string, d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if stderrContains(s) {
				return true
			}
			time.Sleep(40 * time.Millisecond)
		}
		return false
	}

	if !waitFor("event=listening", 5*time.Second) {
		mu.Lock()
		final := stderr.String()
		mu.Unlock()
		t.Fatalf("proxy never became ready:\n%s", final)
	}

	// Client trusts our CA and routes through the proxy. POST a body
	// OVER the default 1 MiB sample cap so it takes the streaming
	// branch; it is well under maxHeldBodyBufferBytes (8 MiB) so #213
	// drains-then-watches it.
	pool := x509.NewCertPool()
	pool.AddCert(dbCA.Cert)
	pURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 25 * time.Second,
	}
	body := strings.Repeat("x", (1<<20)+(64<<10)) // ~1.06 MiB, over the 1 MiB sample cap

	reqCtx, disconnect := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	originURL := fmt.Sprintf("https://%s:%s/held", originHost, originPort)
	go func() {
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, originURL, strings.NewReader(body))
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()

	// Once the inner request is held, disconnect the client.
	if !waitFor("event=request_held", 10*time.Second) {
		mu.Lock()
		final := stderr.String()
		mu.Unlock()
		select {
		case cerr := <-errCh:
			t.Fatalf("inner intercepted request never held; client returned err=%v\nstderr:\n%s", cerr, final)
		default:
			t.Fatalf("inner intercepted request never held (client still in flight):\n%s", final)
		}
	}
	start := time.Now()
	disconnect()

	// The slot must free via hold_abandoned well under timeout_seconds
	// (30s). If #213 regressed, the streaming hold would pin to 30s and
	// this wait would fail.
	if !waitFor("event=hold_abandoned", 6*time.Second) {
		mu.Lock()
		final := stderr.String()
		mu.Unlock()
		t.Fatalf("held slot not freed on disconnect for the streaming body (waiter pinned to timeout):\n%s", final)
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Errorf("hold_abandoned took %v after disconnect; expected prompt release", elapsed)
	}

	// Prove it was the intercept path that was held+abandoned, not the
	// outer CONNECT (insight §37).
	mu.Lock()
	got := stderr.String()
	mu.Unlock()
	abandonedLine := ""
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "event=hold_abandoned") {
			abandonedLine = line
			break
		}
	}
	if !strings.Contains(abandonedLine, "scheme=https-intercepted") {
		t.Errorf("hold_abandoned scheme is not https-intercepted (held the wrong path?):\n%s", abandonedLine)
	}
	<-errCh
}
