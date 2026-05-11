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

// TestSubprocess_StartupEventNamesDaemonMode pins the new
// `event=startup` line emitted by `trollbridge run`. Under
// `--no-console` the line must carry install_mode=daemon and ui=none,
// plus the security-policy posture (default_decision, on_timeout) so
// an operator's first-line answer to "what is this proxy doing?" is
// complete. The line must also fire BETWEEN config_loaded and
// listening — recurring per the trollbridge ask-telemetry-completeness
// memory: partial coverage (one phase only) is the failure shape.
func TestSubprocess_StartupEventNamesDaemonMode(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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

	// Wait for the listening line — by this point startup has fired.
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

	mu.Lock()
	out := stderr.String()
	mu.Unlock()

	if !strings.Contains(out, "event=startup") {
		t.Fatalf("event=startup missing from stderr; got:\n%s", out)
	}

	// Locate the startup line (a single line containing event=startup).
	var startupLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "event=startup") {
			startupLine = line
			break
		}
	}
	if startupLine == "" {
		t.Fatalf("could not locate startup line; stderr:\n%s", out)
	}

	wants := []string{
		"install_mode=daemon",
		"ui=none",
		"default_decision=default-deny",
		"approvals=in-process",
		"on_timeout=deny",
		"version=",
	}
	for _, want := range wants {
		if !strings.Contains(startupLine, want) {
			t.Errorf("startup line missing %q; line: %s", want, startupLine)
		}
	}

	// `mode=daemon` is the wrong key (telemetry pass §2 rejects it).
	// We assert install_mode=daemon above; here we ensure no bare
	// `mode=daemon` token appears on the startup line. mode= stays
	// in use by other lines for cfg.Mode (default-deny|allow|ask).
	// Match only at a word boundary so install_mode=daemon does not
	// false-positive.
	if strings.Contains(startupLine, " mode=daemon") {
		t.Errorf("startup line carries bare `mode=daemon` (collides with policy mode= key); line: %s", startupLine)
	}

	// Ordering: config_loaded < startup < listening.
	cfgIdx := strings.Index(out, "event=config_loaded")
	startupIdx := strings.Index(out, "event=startup")
	listenIdx := strings.Index(out, "event=listening")
	if cfgIdx < 0 || startupIdx < 0 || listenIdx < 0 {
		t.Fatalf("missing one of cfg=%d startup=%d listen=%d", cfgIdx, startupIdx, listenIdx)
	}
	if !(cfgIdx < startupIdx && startupIdx < listenIdx) {
		t.Errorf("ordering broken: config_loaded@%d, startup@%d, listening@%d (want strictly increasing)",
			cfgIdx, startupIdx, listenIdx)
	}

	// Exactly one startup line per process.
	if got := strings.Count(out, "event=startup"); got != 1 {
		t.Errorf("event=startup fires %d times; want 1", got)
	}
}
