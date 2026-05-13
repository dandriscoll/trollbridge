//go:build !windows

package server_test

import (
	"bufio"
	"bytes"
	"context"
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
)

// TestSubprocess_SignalAfterSecondsEmits471WithHoldID closes #43:
// when approvals.signal_after_seconds elapses with a hold still
// pending, the consumer must receive an HTTP 471 with the
// Trollbridge-Hold-Id header set, and the operator log must
// carry an INFO `event=hold_signaled` record. Pre-#43, ordinary
// HTTP clients hung silently for the full timeout_seconds (300s
// default).
func TestSubprocess_SignalAfterSecondsEmits471WithHoldID(t *testing.T) {
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
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	// timeout_seconds is generously long so the hold doesn't
	// resolve via deny-on-timeout during this test; the signal_
	// after path is the only thing that should fire.
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-ask
logging:
  audit_path: %s
approvals:
  timeout_seconds: 60
  signal_after_seconds: 1
  on_timeout: deny
`, proxyPort, auditPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := strings.Contains(stderr.String(), "event=listening")
		mu.Unlock()
		if ready {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	// Drive a plain HTTP request via the proxy. HEAD is sufficient
	// — the proxy's policy evaluation runs before any forward, so
	// the held branch fires regardless of method.
	pURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
		Timeout:   5 * time.Second,
	}
	start := time.Now()
	resp, err := client.Get("http://held.example.test/")
	elapsed := time.Since(start)
	if err != nil {
		mu.Lock()
		final := stderr.String()
		mu.Unlock()
		t.Fatalf("request: %v\nstderr:\n%s", err, final)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 471 {
		t.Errorf("status = %d, want 471 (Trollbridge pending)", resp.StatusCode)
	}
	if got := resp.Header.Get("Trollbridge-Hold-Id"); !strings.HasPrefix(got, "hold-") {
		t.Errorf("Trollbridge-Hold-Id = %q, want a hold-* id", got)
	}
	if got := resp.Header.Get("Trollbridge-Reason"); got != "pending" {
		t.Errorf("Trollbridge-Reason = %q, want %q", got, "pending")
	}

	// The signal_after_seconds is 1s; the response must arrive
	// after roughly 1s and well before the 60s timeout. Bound the
	// elapsed time to catch a regression where the wait-then-
	// signal raced to the wrong branch.
	if elapsed < 800*time.Millisecond || elapsed > 4*time.Second {
		t.Errorf("response arrived after %v; expected ~1s (signal_after_seconds)", elapsed)
	}

	// Stderr must carry the INFO hold_signaled event.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := stderr.String()
		mu.Unlock()
		if strings.Contains(got, "event=hold_signaled") {
			return // pass
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	final := stderr.String()
	mu.Unlock()
	t.Errorf("never observed event=hold_signaled in stderr:\n%s", final)
}

// TestSubprocess_SignalAfterEventualResolutionAudited closes #97:
// when signal_after_seconds fires and the consumer receives a 471
// + disconnects, the eventual resolution of the held request (here
// driven by on_timeout: deny) MUST land in the audit log as a
// follow-up entry sharing the original request_id, with the
// post_signal_resolution marker set. Pre-#97, the eventual
// resolution was only in the oplog; the audit log had only the
// 471-signaled entry, breaking forensic correlation.
func TestSubprocess_SignalAfterEventualResolutionAudited(t *testing.T) {
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
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	// signal_after_seconds: 1 → consumer gets 471 at ~1s.
	// timeout_seconds: 2 → queue's eventual resolution (deny on
	// timeout) fires at ~2s. The post-signal audit entry should
	// appear within a few hundred ms of the 2s mark.
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-ask
logging:
  audit_path: %s
approvals:
  timeout_seconds: 2
  signal_after_seconds: 1
  on_timeout: deny
`, proxyPort, auditPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := strings.Contains(stderr.String(), "event=listening")
		mu.Unlock()
		if ready {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	pURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://held.example.test/")
	if err != nil {
		mu.Lock()
		final := stderr.String()
		mu.Unlock()
		t.Fatalf("request: %v\nstderr:\n%s", err, final)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 471 {
		t.Fatalf("status = %d, want 471 (signaled)", resp.StatusCode)
	}
	requestID := resp.Header.Get("Trollbridge-Request-Id")
	if requestID == "" {
		t.Fatal("missing Trollbridge-Request-Id on the 471 response")
	}

	// Wait for both audit entries: the 471-signaled and the
	// post-signal resolution. The eventual resolution (timeout deny)
	// fires at signal_after + (timeout_seconds - signal_after) ≈
	// 2s total; the audit-write goroutine is async, so allow ~3s
	// of slack on top.
	deadline = time.Now().Add(5 * time.Second)
	var sawSignaled, sawResolution bool
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(auditPath)
		if err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if line == "" {
					continue
				}
				if !strings.Contains(line, `"request_id":"`+requestID+`"`) {
					continue
				}
				if strings.Contains(line, `"decision":"ask_user_signaled"`) {
					sawSignaled = true
				}
				if strings.Contains(line, `"post_signal_resolution":true`) &&
					strings.Contains(line, `"signal_after_seconds":1`) &&
					strings.Contains(line, `"decision":"ask_user_timed_out"`) &&
					strings.Contains(line, `"decision_source":"approval_timeout"`) {
					sawResolution = true
				}
			}
		}
		if sawSignaled && sawResolution {
			return
		}
		time.Sleep(75 * time.Millisecond)
	}
	body, _ := os.ReadFile(auditPath)
	t.Fatalf("audit gap (request_id=%s): sawSignaled=%v sawResolution=%v\naudit:\n%s",
		requestID, sawSignaled, sawResolution, body)
}

// TestSubprocess_SignalAfterSecondsZeroPreservesBlockingBehavior
// pins the back-compat contract: when signal_after_seconds is 0
// (the default), the proxy must continue to block until the
// queue resolves — no early 471. We verify by setting a short
// timeout_seconds and checking the response arrives at ≈timeout
// (deny) rather than at signal time.
func TestSubprocess_SignalAfterSecondsZeroPreservesBlockingBehavior(t *testing.T) {
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
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-ask
logging:
  audit_path: %s
approvals:
  timeout_seconds: 1
  on_timeout: deny
`, proxyPort, auditPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath, "--no-console")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	}()
	time.Sleep(400 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET http://held.example.test/ HTTP/1.1\r\nHost: held.example.test\r\n\r\n"))
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	// Default behavior: response is 470 (declined / timed-out deny),
	// NOT 471. The hold ran out of the timeout_seconds budget.
	if resp.StatusCode != 470 {
		t.Errorf("status = %d, want 470 (declined; timed-out deny)", resp.StatusCode)
	}
	if resp.Header.Get("Trollbridge-Hold-Id") != "" {
		t.Errorf("Trollbridge-Hold-Id should be empty when signal_after_seconds=0; got %q", resp.Header.Get("Trollbridge-Hold-Id"))
	}
}
