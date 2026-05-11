//go:build !windows

package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSubprocess_LogLevelBogusFailsClosed asserts that an invalid
// --log-level value is rejected at startup (exit code 1) with an
// error mentioning the valid set. This is the user-facing failure
// surface; an in-process test would mask cobra's flag-validation
// path.
func TestSubprocess_LogLevelBogusFailsClosed(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("subprocess test relies on POSIX")
	}
	repoRoot := findRepoRoot(t)
	binPath := filepath.Join(t.TempDir(), "trollbridge")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/trollbridge")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, string(out))
	}
	cmd := exec.Command(binPath, "run", "--log-level=trace", "--config=/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; output: %s", string(out))
	}
	if !bytes.Contains(out, []byte("debug")) || !bytes.Contains(out, []byte("warn")) {
		t.Errorf("error did not name the valid set; got: %s", string(out))
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
		}
	}
}

// TestSubprocess_TrollbridgeLogLevelEnvHonored asserts that
// TROLLBRIDGE_LOG_LEVEL=warn suppresses the default INFO startup
// banner, while the same binary at default level emits it.
// Validates the env-precedence path that cobra reads at parse time
// (in-process tests cannot exercise this with the same fidelity).
func TestSubprocess_TrollbridgeLogLevelEnvHonored(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("subprocess test relies on POSIX")
	}
	repoRoot := findRepoRoot(t)
	binPath := filepath.Join(t.TempDir(), "trollbridge")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/trollbridge")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, string(out))
	}

	// Stub origin and config (mirrors the existing subprocess test).
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rulesPath := filepath.Join(dir, "rules.yaml")
	cfgPath := filepath.Join(dir, "trollbridge.yaml")

	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String()
	ctrlLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	rules := fmt.Sprintf("- id: a\n  match: {host: %s}\n  effect: allow\n", originHost)
	os.WriteFile(rulesPath, []byte(rules), 0o600)
	_ = ctrlAddr
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-deny
logging:
  audit_path: %s
approvals:
  timeout_seconds: 5
identities:
  - id: test
    match: {source_ip: 127.0.0.1}
policy:
  include: [%s]
`, proxyPort, auditPath, rulesPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	runOnce := func(envExtra ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath, "--no-console")
		cmd.Env = append(os.Environ(), envExtra...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// Let it print the startup banner and serve one request.
		time.Sleep(400 * time.Millisecond)
		pURL, _ := url.Parse("http://" + proxyAddr)
		c := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(pURL)},
			Timeout:   2 * time.Second,
		}
		resp, err := c.Get(origin.URL)
		if err == nil {
			resp.Body.Close()
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
		return stderr.String()
	}

	defaultOut := runOnce()
	if !strings.Contains(defaultOut, "trollbridge: listening") {
		t.Errorf("default level: expected listening line; got: %s", defaultOut)
	}

	warnOut := runOnce("TROLLBRIDGE_LOG_LEVEL=warn")
	if strings.Contains(warnOut, "trollbridge: listening") {
		t.Errorf("warn level: expected NO listening INFO line; got: %s", warnOut)
	}

	debugOut := runOnce("TROLLBRIDGE_LOG_LEVEL=debug")
	if !strings.Contains(debugOut, "phase=") {
		t.Errorf("debug level: expected per-request phase records; got: %s", debugOut)
	}
}
