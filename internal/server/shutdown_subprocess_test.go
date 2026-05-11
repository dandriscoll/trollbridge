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

// TestSubprocess_ShutdownEventFiresOnSIGTERM closes job 100's filed
// follow-up F2 (`EventShutdown` was dead code — declared but never
// emitted). Boot `trollbridge run --no-console`, send SIGTERM, assert
// the oplog carries `event=shutdown`. Symmetric counterpart to job
// 100's startup-event subprocess assertion.
func TestSubprocess_ShutdownEventFiresOnSIGTERM(t *testing.T) {
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
mode: default-deny
logging:
  audit_path: %s
approvals:
  timeout_seconds: 2
  on_timeout: deny
`, proxyPort, auditPath)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

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

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := strings.Contains(stderr.String(), "event=listening")
		mu.Unlock()
		if ready {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	_ = cmd.Wait()

	mu.Lock()
	out := stderr.String()
	mu.Unlock()

	if !strings.Contains(out, "event=shutdown") {
		t.Fatalf("event=shutdown missing from stderr after SIGTERM; got:\n%s", out)
	}

	// Locate the shutdown line and assert install_mode is present.
	var shutdownLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "event=shutdown") {
			shutdownLine = line
			break
		}
	}
	if !strings.Contains(shutdownLine, "install_mode=daemon") {
		t.Errorf("shutdown line missing install_mode=daemon; line: %q", shutdownLine)
	}
	if !strings.Contains(shutdownLine, "version=") {
		t.Errorf("shutdown line missing version=; line: %q", shutdownLine)
	}
}
