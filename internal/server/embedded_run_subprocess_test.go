//go:build !windows

package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
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

// TestSubprocess_DefaultAskEmitsRequestHeldAtInfo is the
// runtime-classification test that 091/092/093/094/097 all filed
// as a follow-up (closes #47).
//
// Boots `trollbridge run --no-console` with mode: default-ask, no
// allow rules, and a short approvals timeout. Sends a CONNECT
// over the proxy to a host the policy will hold. Verifies stderr
// carries `event=request_held` at INFO with the right host
// before the proxy is killed.
//
// Pre-fix history this pins:
//
//   - #91: the embedded TUI in `trollbridge run` couldn't fetch
//     held requests because of an mTLS cert dependency. The fix
//     made the in-process queue-fetch path work; this test
//     proves the queue actually receives a held request from the
//     real run-mode codepath.
//   - #36: the ask-case-telemetry-completeness class. Pre-fix,
//     held requests weren't visible at INFO. This test pins the
//     INFO-visibility contract end-to-end.
func TestSubprocess_DefaultAskEmitsRequestHeldAtInfo(t *testing.T) {
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

	// default-ask + 2s timeout: an unresolved hold deny-times-out
	// quickly so the test cleanup doesn't have to wait.
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-ask
logging:
  audit_path: %s
approvals:
  timeout_seconds: 2
  on_timeout: deny
`, proxyPort, auditPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Wait for the listening line — proxy is now ready.
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
	mu.Lock()
	startup := stderr.String()
	mu.Unlock()
	if !strings.Contains(startup, "event=listening") {
		t.Fatalf("daemon never listened; stderr:\n%s", startup)
	}

	// Drive a CONNECT through the proxy. We deliberately do NOT
	// wait for the proxy to send its 200 — in default-ask the
	// request is enqueued and our test just needs to confirm the
	// `request_held` event fires. A short read deadline aborts
	// the client side cleanly when the hold doesn't resolve.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	wantHost := "held.example.test"
	connect := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", wantHost, wantHost)
	_, _ = conn.Write([]byte(connect))

	// Poll stderr until the held event surfaces (or 4s elapse).
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := stderr.String()
		mu.Unlock()
		if strings.Contains(got, "event=request_held") && strings.Contains(got, wantHost) {
			return // pass
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	final := stderr.String()
	mu.Unlock()
	t.Fatalf("never observed event=request_held with host=%s; stderr:\n%s", wantHost, final)
}

// lockedWriter is a tiny io.Writer wrapper that serializes writes
// to an underlying *bytes.Buffer so the test's polling reader can
// safely race the subprocess's stderr writer. (bytes.Buffer is
// not goroutine-safe.)
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
