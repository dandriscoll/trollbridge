//go:build e2e

// E2E coverage for `trollbridge run`'s pre-logger startup failures
// (#128): a config that cannot be loaded must produce a structured
// `config_load_failure` operational-log event on stderr before the
// process exits non-zero — not just a bare error line. Before #128
// the configured operational logger did not yet exist at config-load
// time, so these failures reached stderr with no structured event.
//
// Shares the TestMain build-cache with e2e_cli_test.go.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_RunStartup_ConfigLoadFailureIsLogged drives `trollbridge
// run` against a config with an unknown key (which strict decoding,
// #123, rejects) and asserts the process emits a structured
// `event=config_load_failure` line to stderr and exits non-zero.
func TestE2E_RunStartup_ConfigLoadFailureIsLogged(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	// `bogus_key` has no matching Config field, so config.Load fails
	// before the configured operational logger is constructed.
	body := "proxy: lo:8080\nbogus_key: true\n"
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "run", "-c", yamlPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("trollbridge run on a bad config should exit non-zero\n%s", out)
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if !strings.Contains(string(out), "event=config_load_failure") {
		t.Errorf("startup failure should carry a structured config_load_failure event:\n%s", out)
	}
}
