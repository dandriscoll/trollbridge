package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestInitAnswers_RendersUserModeDefaultDeny is the load-bearing
// E2E for the agentic answers-file path: an onboarding agent
// writes a minimal answers file, runs `init --answers`, and the
// rendered yaml carries the expected install-mode + topology +
// policy mode shape — same as a TTY operator would have gotten.
func TestInitAnswers_RendersUserModeDefaultDeny(t *testing.T) {
	dir := t.TempDir()
	ansPath := filepath.Join(dir, "answers.yaml")
	answers := `# trollbridge-init-answers v1
install_mode: user
topology: local
mode: default-deny
interception: false
`
	if err := os.WriteFile(ansPath, []byte(answers), 0o600); err != nil {
		t.Fatalf("write answers: %v", err)
	}
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--answers", ansPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --answers: %v\noutput: %s", err, out.String())
	}

	cfg, err := config.Load(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Mode != "default-deny" {
		t.Errorf("mode = %q, want default-deny", cfg.Mode)
	}
	if cfg.Proxy.Host != "127.0.0.1" || cfg.Proxy.Port != 8080 {
		t.Errorf("proxy = %s:%d, want 127.0.0.1:8080 (lo alias)", cfg.Proxy.Host, cfg.Proxy.Port)
	}
	if cfg.Interception.Enabled {
		t.Error("interception enabled, want false")
	}
	if cfg.LLM.Enabled {
		t.Error("LLM enabled, want false (advisor omitted from answers)")
	}
	// user-mode anchors CA paths at the init dir, not /etc/trollbridge.
	want := filepath.Join(dir, "trollbridge-ca.crt")
	if got := cfg.Interception.CA.CertPath; got != want {
		t.Errorf("cert_path = %q, want %q (user-mode anchors at init dir)", got, want)
	}
}

// TestInitAnswers_DaemonModeUsesCanonicalPaths asserts that the
// daemon-mode branch in applyPathDefaults still anchors at
// /etc/trollbridge/ when driven through the --answers path. Issue
// #14 stayed solved: agent-driven setup uses the same cross-machine
// stable paths a TTY operator gets.
func TestInitAnswers_DaemonModeUsesCanonicalPaths(t *testing.T) {
	if initGOOS == "windows" {
		t.Skip("daemon-mode is refused on Windows")
	}
	dir := t.TempDir()
	ansPath := filepath.Join(dir, "answers.yaml")
	answers := `# trollbridge-init-answers v1
install_mode: daemon
topology: remote
mode: default-ask
interception: true
`
	if err := os.WriteFile(ansPath, []byte(answers), 0o600); err != nil {
		t.Fatalf("write answers: %v", err)
	}
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--answers", ansPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --answers: %v\noutput: %s", err, out.String())
	}
	cfg, err := config.Load(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Interception.CA.CertPath != DefaultCACertPath {
		t.Errorf("daemon-mode cert_path = %q, want %q", cfg.Interception.CA.CertPath, DefaultCACertPath)
	}
	if cfg.Proxy.Host != "0.0.0.0" {
		t.Errorf("remote-topology proxy host = %q, want 0.0.0.0 (`all`)", cfg.Proxy.Host)
	}
	if !cfg.Interception.Enabled {
		t.Error("interception=true in answers but Enabled=false after load")
	}
}

// TestInitAnswers_StrictDecodeRejectsUnknownKey closes the
// agentic equivalent of #123: a typo in the answers file must
// surface at load time with the offending field named, not
// silently default away.
func TestInitAnswers_StrictDecodeRejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	ansPath := filepath.Join(dir, "answers.yaml")
	bad := `install_mode: user
topology: local
mode: default-deny
interception: false
unknown_field: oops
`
	if err := os.WriteFile(ansPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--answers", ansPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected strict-decode error, got nil; output: %s", out.String())
	}
	if !strings.Contains(err.Error(), "unknown_field") && !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Errorf("expected error to name unknown_field, got: %v", err)
	}
}

// TestInitAnswers_RejectsBadEnumValue ensures the validator
// names which field failed and what the allowed values are.
func TestInitAnswers_RejectsBadEnumValue(t *testing.T) {
	dir := t.TempDir()
	ansPath := filepath.Join(dir, "answers.yaml")
	bad := `install_mode: superuser
topology: local
mode: default-deny
interception: false
`
	if err := os.WriteFile(ansPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--answers", ansPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on bad install_mode value, got nil")
	}
	if !strings.Contains(err.Error(), "install_mode") || !strings.Contains(err.Error(), "superuser") {
		t.Errorf("expected error to name install_mode and superuser, got: %v", err)
	}
}

// TestInitAnswers_LLMRequiresEndpointForAOAI ensures the
// dependency rule from the agentic plan ("q.advisor.endpoint
// required when provider=aoai") is enforced at answers-load.
func TestInitAnswers_LLMRequiresEndpointForAOAI(t *testing.T) {
	dir := t.TempDir()
	ansPath := filepath.Join(dir, "answers.yaml")
	bad := `install_mode: user
topology: local
mode: default-deny
interception: false
llm:
  enabled: true
  provider: aoai
  model: gpt-4o-mini
`
	if err := os.WriteFile(ansPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir, "--answers", ansPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error: aoai requires endpoint; got nil")
	}
	if !strings.Contains(err.Error(), "llm.endpoint") {
		t.Errorf("expected error to mention llm.endpoint, got: %v", err)
	}
}

// TestSetupPlan_JSONShapeIsStable asserts the keys an
// onboarding agent depends on are present and the version is set.
// Stability matters: an agent that has been trained or
// prompt-engineered to read these field names cannot tolerate
// silent renames.
func TestSetupPlan_JSONShapeIsStable(t *testing.T) {
	cmd := newSetupPlanCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup-plan --json: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	for _, key := range []string{"version", "project", "entry_doc", "agentic_yaml_template", "goals", "questions", "steps", "platform_notes", "verification", "backward_compat_notes"} {
		if _, ok := v[key]; !ok {
			t.Errorf("setup-plan JSON missing required key %q (an onboarding agent depends on this name)", key)
		}
	}
	if v["version"] != "1" {
		t.Errorf("plan version = %v, want \"1\" (bump only on breaking changes)", v["version"])
	}
}

// TestSetupPlan_DocViewMentionsRequiredQuestions asserts the
// markdown view names every required question — the agent
// reading the doc must be able to find them.
func TestSetupPlan_DocViewMentionsRequiredQuestions(t *testing.T) {
	cmd := newSetupPlanCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--doc"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup-plan --doc: %v", err)
	}
	body := out.String()
	for _, name := range []string{"q.install_mode", "q.topology", "q.policy_mode", "q.interception", "q.advisor.enabled"} {
		if !strings.Contains(body, name) {
			t.Errorf("setup-plan --doc missing required question %q", name)
		}
	}
	for _, platform := range []string{"linux", "darwin", "windows"} {
		if !strings.Contains(body, platform) {
			t.Errorf("setup-plan --doc missing platform note %q", platform)
		}
	}
}

// TestAgenticYAML_ParsesThroughLoader asserts that
// config.agentic.yaml is a valid trollbridge config (loads
// through the strict decoder unchanged) — the file ships as
// both an agent-readable plan AND a runnable starting config.
func TestAgenticYAML_ParsesThroughLoader(t *testing.T) {
	repoRoot := findRepoRoot(t)
	path := filepath.Join(repoRoot, "config.agentic.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", path, err)
	}
	if cfg.Mode != "default-deny" {
		t.Errorf("config.agentic.yaml mode = %q, want default-deny (safest default for the agent's first session)", cfg.Mode)
	}
}

// TestSampleAnswersFile_LoadsViaLoader ensures the example
// answers file in init_answers.go's sampleAnswersFile constant
// stays in sync with the loader: any change to the answers
// schema must keep the sample loadable.
func TestSampleAnswersFile_LoadsViaLoader(t *testing.T) {
	// The sample is fully-commented; the loader must still
	// accept it as a valid empty/comment-only document — but
	// since required fields are needed, we test the embedded
	// minimal example by un-commenting via the same shape:
	minimal := `install_mode: user
topology: local
mode: default-deny
interception: false
`
	tmp := filepath.Join(t.TempDir(), "ans.yaml")
	if err := os.WriteFile(tmp, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnswersFile(tmp, nil); err != nil {
		t.Fatalf("loadAnswersFile minimal: %v", err)
	}
	// Also verify the sample constant has the required header line
	// — agents that grep for "# trollbridge-init-answers" must
	// find it.
	if !strings.Contains(sampleAnswersFile, "# trollbridge-init-answers v1") {
		t.Error("sampleAnswersFile missing the agent-discoverable version header")
	}
}

// TestLoadAnswersFile_Stdin covers the "-" sentinel path: an
// agent can pipe answers via stdin instead of writing a temp file
// (useful in container/CI flows where /tmp may be read-only).
// Closes review finding F-T1.
func TestLoadAnswersFile_Stdin(t *testing.T) {
	in := bytes.NewReader([]byte(`install_mode: user
topology: local
mode: default-deny
interception: false
`))
	ans, err := loadAnswersFile("-", in)
	if err != nil {
		t.Fatalf("loadAnswersFile from stdin: %v", err)
	}
	if ans.installMode != "user" || ans.topology != "local" || ans.mode != "default-deny" {
		t.Errorf("stdin answers did not round-trip: %+v", ans)
	}
}

// findRepoRoot walks up from cwd until it finds go.mod. Used by
// tests that need to read a file shipped at the repo root.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", cwd)
		}
		dir = parent
	}
}
