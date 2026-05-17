//go:build e2e

// E2E coverage for `trollbridge validate` — the operator-facing
// surface whose entire job is to catch config mistakes. Issue #123:
// before strict YAML decoding, `validate` reported OK on a config
// full of unknown keys. These tests drive the built binary as a
// subprocess and assert validate now exits non-zero and names the
// offending key on an unknown key in both the config file and an
// included rule file — and still passes on a clean config.
//
// Run with:
//
//   go test -tags=e2e ./cmd/trollbridge/... -run E2E_Validate
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

// runValidate runs `trollbridge validate -c <path>` against the e2e
// binary and returns combined stdout+stderr plus the process exit
// code (0 on success).
func runValidate(t *testing.T, configPath string) (string, int) {
	t.Helper()
	cmd := exec.Command(e2eBinary, "validate", "-c", configPath)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("validate: unexpected error type %T: %v", err, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// runValidateJSON runs `trollbridge validate --json -c <path>` and
// returns stdout (the JSON object), stderr separately (operators
// expect --json to keep stdout pure), and the exit code.
func runValidateJSON(t *testing.T, configPath string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(e2eBinary, "validate", "--json", "-c", configPath)
	var soBuf, seBuf strings.Builder
	cmd.Stdout = &soBuf
	cmd.Stderr = &seBuf
	err := cmd.Run()
	code = 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("validate --json: unexpected error type %T: %v", err, err)
		}
		code = ee.ExitCode()
	}
	return soBuf.String(), seBuf.String(), code
}

// TestE2E_Validate_CleanConfigPasses is the baseline: a config with
// only known keys validates OK with exit 0. Proves strict decoding
// did not break the out-of-the-box path.
func TestE2E_Validate_CleanConfigPasses(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `proxy: lo:8080
control: 0
metrics: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl}
interception: {enabled: false}
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runValidate(t, yamlPath)
	if code != 0 {
		t.Errorf("clean config: validate exited %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("clean config: validate output missing `OK`:\n%s", out)
	}
}

// TestE2E_Validate_UnknownConfigKeyFails closes the issue's headline
// symptom: an unknown top-level key (the dev-era `trollbridge_version`,
// dropped from the schema in e38ee83) must make `trollbridge validate`
// exit non-zero and name the offending key.
func TestE2E_Validate_UnknownConfigKeyFails(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `trollbridge_version: 3
proxy: lo:8080
control: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl}
interception: {enabled: false}
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runValidate(t, yamlPath)
	if code == 0 {
		t.Errorf("unknown config key: validate exited 0, want non-zero\n%s", out)
	}
	if !strings.Contains(out, "trollbridge_version") {
		t.Errorf("unknown config key: validate output should name `trollbridge_version`:\n%s", out)
	}
}

// TestE2E_Validate_JSONCleanConfig pins #127's success-path contract:
// `validate --json` against a clean config exits 0, emits a single
// JSON object on stdout with `ok=true` and the descriptive fields
// populated, and produces no stderr. Operators bind this from their
// own CI.
func TestE2E_Validate_JSONCleanConfig(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `proxy: lo:8080
control: 0
metrics: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl}
interception: {enabled: false}
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runValidateJSON(t, yamlPath)
	if code != 0 {
		t.Errorf("clean config --json: exit %d, want 0; stdout=%s stderr=%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Errorf("clean config --json: stderr should be empty; got %q", stderr)
	}
	var got struct {
		OK             bool   `json:"ok"`
		Config         string `json:"config"`
		Mode           string `json:"mode"`
		RuleSetVersion string `json:"rule_set_version"`
		Rules          *struct {
			Count int `json:"count"`
		} `json:"rules"`
		Lists *struct {
			Allow int `json:"allow"`
			Deny  int `json:"deny"`
		} `json:"lists"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("clean config --json: stdout is not valid JSON: %v\nstdout=%s", err, stdout)
	}
	if !got.OK {
		t.Errorf("clean config --json: ok=false on a clean config; payload=%s", stdout)
	}
	if got.Config != yamlPath {
		t.Errorf("clean config --json: config=%q, want %q", got.Config, yamlPath)
	}
	if got.Mode != "default-deny" {
		t.Errorf("clean config --json: mode=%q, want default-deny", got.Mode)
	}
	if got.Error != nil {
		t.Errorf("clean config --json: error field set on success: %+v", got.Error)
	}
}

// TestE2E_Validate_JSONUnknownKey pins #127's failure-path contract:
// `validate --json` against a config with an unknown key exits 1,
// emits a single JSON object on stdout with `ok=false` and an
// `error.message` naming the offending key.
func TestE2E_Validate_JSONUnknownKey(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `trollbridge_version: 3
proxy: lo:8080
control: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl}
interception: {enabled: false}
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runValidateJSON(t, yamlPath)
	if code != 1 {
		t.Errorf("unknown key --json: exit %d, want 1; stdout=%s", code, stdout)
	}
	var got struct {
		OK    bool   `json:"ok"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unknown key --json: stdout is not valid JSON: %v\nstdout=%s", err, stdout)
	}
	if got.OK {
		t.Errorf("unknown key --json: ok=true on an invalid config; payload=%s", stdout)
	}
	if got.Error == nil || !strings.Contains(got.Error.Message, "trollbridge_version") {
		t.Errorf("unknown key --json: error.message should name `trollbridge_version`; payload=%s", stdout)
	}
}

// TestE2E_Validate_UnknownRuleKeyFails extends the same guarantee to
// included rule files: an unknown match sub-key (`math:` for
// `method:`) — the case that silently broadens a security rule under
// lenient decoding — must fail `validate`.
func TestE2E_Validate_UnknownRuleKeyFails(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	rulesBody := `- id: broadened
  match:
    host: example.com
    math: ["GET"]
  effect: allow
`
	if err := os.WriteFile(rulesPath, []byte(rulesBody), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	body := `proxy: lo:8080
control: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: ` + dir + `/audit.jsonl}
interception: {enabled: false}
policy:
  include:
    - rules.yaml
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runValidate(t, yamlPath)
	if code == 0 {
		t.Errorf("unknown rule key: validate exited 0, want non-zero\n%s", out)
	}
	if !strings.Contains(out, "math") {
		t.Errorf("unknown rule key: validate output should name `math`:\n%s", out)
	}
}
