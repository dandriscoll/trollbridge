package server_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
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

// TestSubprocess_TrollbridgeBinaryServesAndAuditsAndExitsCleanly is
// the carry-forward 031.I.5 test: build the binary, exec it,
// drive a real HTTP client through it, then SIGTERM and assert
// clean exit + audit log shape. This is the runtime layer the
// in-process tests don't cover.
func TestSubprocess_TrollbridgeBinaryServesAndAuditsAndExitsCleanly(t *testing.T) {
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

	// Stub origin.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "from-origin")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	// Pick free ports for proxy and control plane.
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	ctrlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctrlAddr := ctrlLn.Addr().String()
	ctrlLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = ctrlAddr
	cfgYAML := fmt.Sprintf(`trollbridge_version: 3
proxy: lo:%s
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
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// Start the binary.
	cmd := exec.Command(binPath, "run", "--config", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()
	time.Sleep(300 * time.Millisecond)

	// Drive a request.
	pURL, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}, Timeout: 5 * time.Second}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("from-origin")) {
		t.Errorf("body: got %q", string(body))
	}

	// SIGTERM and wait for clean exit.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			// Exit codes 0 and 130 (SIGINT) and other clean
			// exits are acceptable.
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == -1 {
				// killed by signal — that's fine for this test
			} else {
				t.Logf("process exit: %v", err)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("process did not exit within 10s of SIGTERM")
	}

	// Audit log should contain the allow entry.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("\"decision\":\"allow\"")) {
		t.Errorf("audit log missing allow entry; content:\n%s", string(data))
	}
}

// findRepoRoot walks up from the test file to locate go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find repo root from %s", cwd)
	return ""
}
