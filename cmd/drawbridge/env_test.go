package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalConfig writes a drawbridge.yaml into a temp dir with just
// enough fields to satisfy config.Load; returns the path.
func minimalConfig(t *testing.T, listenAddress string, listenPort int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "drawbridge.yaml")
	adapter := listenAddress
	if listenAddress == "127.0.0.1" {
		adapter = "lo"
	}
	body := []byte(strings.Join([]string{
		"drawbridge_version: 2",
		"adapter: " + adapter,
		"ports:",
		fmt.Sprintf("  proxy: %d", listenPort),
		"  control: 0",
		"mode: default-deny",
		"controller: {auth: mtls}",
		"approvals: {timeout_seconds: 60, on_timeout: deny, max_pending: 16}",
		"logging:",
		"  audit_path: " + filepath.Join(dir, "audit.log"),
		"  operational_path: " + filepath.Join(dir, "ops.log"),
		"",
	}, "\n"))
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestEnvCmdEmitsExports(t *testing.T) {
	cfgPath := minimalConfig(t, "127.0.0.1", 8080)

	var stdout bytes.Buffer
	cmd := newEnvCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"-c", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	for _, want := range []string{
		"export HTTPS_PROXY=http://127.0.0.1:8080",
		"export HTTP_PROXY=http://127.0.0.1:8080",
		"export NO_PROXY=localhost,127.0.0.1",
		"export https_proxy=http://127.0.0.1:8080",
		"export http_proxy=http://127.0.0.1:8080",
		"export no_proxy=localhost,127.0.0.1",
		"# drawbridge env:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestEnvCmdWildcardBecomesLoopback(t *testing.T) {
	cfgPath := minimalConfig(t, "0.0.0.0", 9090)

	var stdout bytes.Buffer
	cmd := newEnvCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"-c", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "export HTTPS_PROXY=http://127.0.0.1:9090") {
		t.Errorf("0.0.0.0 should have rendered as 127.0.0.1; got:\n%s", out)
	}
	if strings.Contains(out, "0.0.0.0") {
		t.Errorf("output should not leak the 0.0.0.0 wildcard:\n%s", out)
	}
}
