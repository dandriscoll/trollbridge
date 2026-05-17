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

// TestE2E_RunStartup_PolicyEngineFailureIsLogged closes #134's
// post-opLog slice: the main config parses cleanly, the operational
// log opens, then `policy.NewEngine` fails because an included
// rules file carries the unsupported `tool:` clause (#125). The
// daemon must emit a structured `event=startup_failure stage=policy`
// line via the real operational logger before exiting non-zero.
// Before #134 these post-opLog failures left the operational log
// silent on why the daemon failed to come up.
func TestE2E_RunStartup_PolicyEngineFailureIsLogged(t *testing.T) {
	dir := t.TempDir()

	// Rules file with the post-#125 unsupported clause; strict
	// decode rejects it at policy.NewEngine load time, AFTER the
	// operational logger is constructed.
	rulesPath := filepath.Join(dir, "rules.yaml")
	rulesBody := `- id: rejected
  match:
    host: example.com
    tool: claude-code
  effect: allow
`
	if err := os.WriteFile(rulesPath, []byte(rulesBody), 0o600); err != nil {
		t.Fatal(err)
	}

	// Main config parses cleanly and includes the broken rules
	// file. The operational log goes to stderr so the test can
	// observe the structured event.
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `proxy: lo:8080
control: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl, operational_path: stderr}
interception: {enabled: false}
policy:
  include:
    - rules.yaml
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "run", "-c", yamlPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("trollbridge run on a bad rules file should exit non-zero\n%s", out)
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	combined := string(out)
	if !strings.Contains(combined, "event=startup_failure") {
		t.Errorf("post-opLog startup failure should carry a structured startup_failure event:\n%s", combined)
	}
	if !strings.Contains(combined, "stage=policy") {
		t.Errorf("post-opLog startup failure should carry the failing stage attribute:\n%s", combined)
	}
	// The underlying error names the offending key — operators
	// rely on the error attribute to know where to look.
	if !strings.Contains(combined, "tool") {
		t.Errorf("startup_failure log line should surface the underlying error mentioning `tool`:\n%s", combined)
	}
}
