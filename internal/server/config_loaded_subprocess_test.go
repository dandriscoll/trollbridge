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
	"syscall"
	"testing"
	"time"
)

// TestSubprocess_ConfigLoadedLogIsAtInfoLevel pins the #45 contract:
// `trollbridge run` emits an INFO oplog event on startup naming the
// absolute path of the config file it loaded. The line removes the
// "I edited config X but the proxy uses config Y" diagnostic class
// that surfaced during the syntagma wedge investigation (job 091).
func TestSubprocess_ConfigLoadedLogIsAtInfoLevel(t *testing.T) {
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
`, proxyPort, auditPath)
	os.WriteFile(cfgPath, []byte(cfgYAML), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath, "--no-console")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	_ = cmd.Wait()

	out := stderr.String()
	wantPath, _ := filepath.Abs(cfgPath)

	for _, want := range []string{
		"event=config_loaded",
		"path=" + wantPath,
		"mode=default-deny",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in startup log; got:\n%s", want, out)
		}
	}

	// The config_loaded line must appear *before* the listening line
	// — operators reading the journal top-down should see "what was
	// loaded" before "where we're listening."
	cfgIdx := strings.Index(out, "event=config_loaded")
	listenIdx := strings.Index(out, "event=listening")
	if cfgIdx < 0 || listenIdx < 0 {
		t.Fatalf("missing one of config_loaded/listening events; got:\n%s", out)
	}
	if cfgIdx > listenIdx {
		t.Errorf("config_loaded must precede listening; cfgIdx=%d listenIdx=%d", cfgIdx, listenIdx)
	}
}
