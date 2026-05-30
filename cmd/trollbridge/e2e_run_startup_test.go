//go:build e2e

// E2E coverage for `trollbridge run`'s pre-logger startup failures
// (#128): a config that cannot be loaded must produce a structured
// `config_load_failure` operational-log event on stderr before the
// process exits non-zero — not just a bare error line. Before #128
// the configured operational logger did not yet exist at config-load
// time, so these failures reached stderr with no structured event.
//
// Also covers `trollbridge verify` against a running daemon (#149).
//
// Shares the TestMain build-cache with e2e_cli_test.go.

package main

import (
	"encoding/json"
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

// TestE2E_RunStartup_AuditInitFailureIsLogged closes one branch of
// #146: when audit.New() cannot construct, the operational log
// emits `event=startup_failure stage=audit` before the process
// exits.
//
// Cross-OS portable mechanism: pre-create the audit_path itself
// as a DIRECTORY. audit.New's OpenFile(path, O_CREATE|O_APPEND
// |O_WRONLY) then fails with "is a directory" on Unix
// (syscall.EISDIR) or ERROR_ACCESS_DENIED on Windows — both
// surface as a stage=audit failure. The earlier mode-based
// approach (`os.Mkdir(auditDir, 0o500)`) hung on Windows because
// the OS ignores Unix mode bits and the binary started normally
// (#163 Phase 2 round 2).
func TestE2E_RunStartup_AuditInitFailureIsLogged(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.Mkdir(auditPath, 0o755); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := "proxy: lo:8080\nlogging:\n  audit_path: " + auditPath + "\n  operational_path: stderr\n"
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "run", "-c", yamlPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("trollbridge run with audit_path resolving to a directory should exit non-zero\n%s", out)
	}
	combined := string(out)
	if !strings.Contains(combined, "event=startup_failure") {
		t.Errorf("audit-init failure should carry structured startup_failure event:\n%s", combined)
	}
	if !strings.Contains(combined, "stage=audit") {
		t.Errorf("audit-init failure should name stage=audit:\n%s", combined)
	}
}

// testInjectStartupFailure invokes the binary with
// TROLLBRIDGE_TEST_FAIL_STAGE=<stage> set and asserts the resulting
// operational-log stream carries `event=startup_failure stage=<stage>`
// before the process exits non-zero (#166). The minimal config used
// here passes all earlier stages so each named stage is reached.
func testInjectStartupFailure(t *testing.T, stage string) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	yaml := "proxy: lo:8080\ncontrol: 0\nmode: default-deny\nlogging:\n  audit_path: " + auditPath + "\n  operational_path: stderr\n"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(e2eBinary, "run", "-c", yamlPath)
	cmd.Env = append(os.Environ(), "TROLLBRIDGE_TEST_FAIL_STAGE="+stage)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("forced %s-stage failure should exit non-zero:\n%s", stage, out)
	}
	combined := string(out)
	if !strings.Contains(combined, "event=startup_failure") {
		t.Errorf("forced %s-stage failure should carry structured startup_failure event:\n%s", stage, combined)
	}
	if !strings.Contains(combined, "stage="+stage) {
		t.Errorf("forced %s-stage failure should name stage=%s:\n%s", stage, stage, combined)
	}
}

// TestE2E_RunStartup_AuditLevelInjected closes #166's audit_level
// branch via TROLLBRIDGE_TEST_FAIL_STAGE=audit_level.
func TestE2E_RunStartup_AuditLevelInjected(t *testing.T) {
	testInjectStartupFailure(t, "audit_level")
}

// TestE2E_RunStartup_ServerInjected closes #166's server branch.
func TestE2E_RunStartup_ServerInjected(t *testing.T) {
	testInjectStartupFailure(t, "server")
}

// TestE2E_RunStartup_ListsInjected closes #166's lists branch.
func TestE2E_RunStartup_ListsInjected(t *testing.T) {
	testInjectStartupFailure(t, "lists")
}

// TestE2E_VerifyAgainstRunningDaemon closes #149: spawn the binary
// with a minimal config, wait for the proxy port, then run
// `trollbridge verify --json -c <cfg>` and assert ok=true plus the
// confirmation fields are non-empty. verify is the agent's done-check;
// a regression in its output shape would silently break agentic
// onboarding.
func TestE2E_VerifyAgainstRunningDaemon(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	// Reuse writeE2EYaml's shape so the running daemon has the same
	// audit / oplog wiring the other e2e tests rely on.
	yamlPath := writeE2EYaml(t, dir, port, []string{"example.com"})
	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	cmd := exec.Command(e2eBinary, "verify", "--json", "-c", yamlPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// verify exits non-zero when ok=false; for our minimal-allow
		// fixture above, the verify must succeed cleanly.
		t.Fatalf("trollbridge verify --json failed: %v\n%s", err, out)
	}
	// The CombinedOutput may carry a human-readable banner before
	// the JSON; --json puts the structured doc on stdout. Find the
	// first '{' and unmarshal from there.
	start := strings.IndexByte(string(out), '{')
	if start < 0 {
		t.Fatalf("verify output has no JSON object:\n%s", out)
	}
	var res struct {
		OK             bool     `json:"ok"`
		ConfigParses   bool     `json:"config_parses"`
		ProxyReachable bool     `json:"proxy_reachable"`
		Confirmations  []string `json:"confirmations"`
		Gaps           []struct {
			ID       string `json:"id"`
			BlocksOK bool   `json:"blocks_ok"`
		} `json:"gaps"`
	}
	if jerr := json.Unmarshal(out[start:], &res); jerr != nil {
		t.Fatalf("verify --json output did not parse as JSON: %v\nraw output:\n%s", jerr, string(out[start:]))
	}
	if !res.OK {
		var blocking []string
		for _, g := range res.Gaps {
			if g.BlocksOK {
				blocking = append(blocking, g.ID)
			}
		}
		t.Fatalf("verify ok=false; blocking gaps=%v; full output:\n%s", blocking, out)
	}
	if !res.ConfigParses {
		t.Errorf("config_parses=false in verify result:\n%s", out)
	}
	if !res.ProxyReachable {
		t.Errorf("proxy_reachable=false in verify result:\n%s", out)
	}
	if len(res.Confirmations) < 2 {
		t.Errorf("expected at least two confirmations (config parse + proxy reachable); got %v\n%s", res.Confirmations, out)
	}
}
