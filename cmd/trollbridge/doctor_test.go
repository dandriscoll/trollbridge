package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// minimalDoctorYaml writes a v3 trollbridge.yaml for doctor tests.
// llmEnabled controls whether the llm block is enabled; the
// fixture also writes a rules.yaml referenced by policy.include.
func minimalDoctorYaml(t *testing.T, llmEnabled bool) string {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	mustWrite(t, rulesPath, "")
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	llmBlock := "llm:\n  enabled: false\n"
	if llmEnabled {
		llmBlock = strings.Join([]string{
			"llm:",
			"  enabled: true",
			"  provider: anthropic",
			"  endpoint: https://example.invalid",
			"  timeout_seconds: 2",
			"",
		}, "\n")
	}
	body := strings.Join([]string{
		"proxy: lo:8080",
		"control: 0",
		"controller: {auth: mtls}",
		"mode: default-deny",
		"logging: {audit_path: " + filepath.Join(dir, "audit.jsonl") + "}",
		"policy:",
		"  include:",
		"    - " + rulesPath,
		llmBlock,
		"",
	}, "\n")
	mustWrite(t, cfgPath, body)
	return cfgPath
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDoctor_LlmDisabled_ReportsSkip(t *testing.T) {
	cfgPath := minimalDoctorYaml(t, false)
	var stdout bytes.Buffer

	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"-c", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "config:") || !strings.Contains(out, "OK ("+cfgPath) {
		t.Errorf("config line missing or not OK in:\n%s", out)
	}
	for _, want := range []string{"rules:", "lists:", "llm:", "skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDoctor_LlmHappyPath_ReportsOK(t *testing.T) {
	cfgPath := minimalDoctorYaml(t, true)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{
		Output: advisor.Output{Effect: "allow", Confidence: "high", Reason: "ok"},
	}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "llm:") {
		t.Errorf("missing llm: line in:\n%s", out)
	}
	for _, want := range []string{"OK (provider=anthropic", "effect=allow", "confidence=high"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestDoctor_LlmHappyPath_AnnouncesContactBeforeResult asserts the
// progress line that closes issue #9: doctor must print an
// in-flight "contacting …" status line *before* the synchronous
// classification call, so operators do not see a hung terminal
// during the up-to-(timeout+2)s wait.
func TestDoctor_LlmHappyPath_AnnouncesContactBeforeResult(t *testing.T) {
	cfgPath := minimalDoctorYaml(t, true)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{
		Output: advisor.Output{Effect: "allow", Confidence: "high", Reason: "ok"},
	}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := stdout.String()

	contactIdx := strings.Index(out, "contacting provider=anthropic")
	if contactIdx < 0 {
		t.Fatalf("doctor did not announce LLM contact before the call; got:\n%s", out)
	}
	for _, want := range []string{"endpoint=https://example.invalid", "auth=x-api-key", "timeout 2s"} {
		if !strings.Contains(out, want) {
			t.Errorf("contacting line missing %q in:\n%s", want, out)
		}
	}
	okIdx := strings.Index(out, "OK (provider=anthropic")
	if okIdx < 0 {
		t.Fatalf("missing OK line in:\n%s", out)
	}
	if contactIdx > okIdx {
		t.Errorf("contacting line must precede OK line; got contactIdx=%d okIdx=%d in:\n%s",
			contactIdx, okIdx, out)
	}
}

func TestDoctor_LlmDispatchError_ReturnsRuntimeErr(t *testing.T) {
	cfgPath := minimalDoctorYaml(t, true)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{Err: errors.New("simulated 401")}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute: expected error from doctor on advisor failure")
	}
	var re *runtimeErr
	if !errors.As(err, &re) {
		t.Errorf("expected runtimeErr, got %T: %v", err, err)
	}
	if !strings.Contains(stdout.String(), "FAIL") {
		t.Errorf("doctor should have printed a FAIL line; got:\n%s", stdout.String())
	}
}

// minimalDoctorYamlWithKeyPath writes a v3 trollbridge.yaml whose
// llm block has enabled=true and api_key_path set to the supplied
// path. Used to exercise the early-file-check behavior added by
// closure for #82.
func minimalDoctorYamlWithKeyPath(t *testing.T, apiKeyPath string) string {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	mustWrite(t, rulesPath, "")
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	body := strings.Join([]string{
		"proxy: lo:8080",
		"control: 0",
		"controller: {auth: mtls}",
		"mode: default-deny",
		"logging: {audit_path: " + filepath.Join(dir, "audit.jsonl") + "}",
		"policy:",
		"  include:",
		"    - " + rulesPath,
		"llm:",
		"  enabled: true",
		"  provider: anthropic",
		"  endpoint: https://example.invalid",
		"  api_key_path: " + apiKeyPath,
		"  timeout_seconds: 2",
		"",
	}, "\n")
	mustWrite(t, cfgPath, body)
	return cfgPath
}

// TestDoctor_LLMEnabledMissingKeyFile_FailsEarly closes the silent
// empty-key class. When llm.enabled and api_key_path names a file
// that does not exist, doctor must FAIL the llm step with a message
// naming the path — without making any wire call (closes #82).
func TestDoctor_LLMEnabledMissingKeyFile_FailsEarly(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "nonexistent-llm.key")
	cfgPath := minimalDoctorYamlWithKeyPath(t, missingPath)

	// Install a stub advisor that would fail the test if called —
	// the whole point of the early file-check is that we never
	// reach the wire call.
	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{Err: errors.New("advisor should not have been called")}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute: expected error for missing api_key_path; got success\n%s", stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{"llm:", "FAIL", "api_key_path", missingPath, "does not exist or is unreadable"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Doctor must not have announced the contact line — the wire
	// call should never have started.
	if strings.Contains(out, "contacting provider=") {
		t.Errorf("doctor reached the wire call despite missing api_key_path; got:\n%s", out)
	}
}

// TestDoctor_LLMEnabledUnreadableKeyFile_FailsEarly: api_key_path is
// a directory, not a regular file. Doctor must FAIL with the same
// shape — os.ReadFile returns an error in both ENOENT and "is a
// directory" cases (closes #82).
func TestDoctor_LLMEnabledUnreadableKeyFile_FailsEarly(t *testing.T) {
	dirAsPath := t.TempDir() // path exists, but it is a directory
	cfgPath := minimalDoctorYamlWithKeyPath(t, dirAsPath)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{Err: errors.New("advisor should not have been called")}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute: expected error for directory api_key_path; got success\n%s", stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{"llm:", "FAIL", "api_key_path", "does not exist or is unreadable"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestDoctor_CheckLLMFlag_ForcesLLMStep: --check-llm runs the LLM
// classification step even when llm.enabled is false in the YAML.
// Useful for verifying provider wiring before flipping the
// production switch (closes #82).
func TestDoctor_CheckLLMFlag_ForcesLLMStep(t *testing.T) {
	// minimalDoctorYaml with llmEnabled=false leaves the llm block
	// empty. Need a yaml that has the llm block populated (provider,
	// endpoint, model) but with enabled=false — build it inline.
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	mustWrite(t, rulesPath, "")
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	body := strings.Join([]string{
		"proxy: lo:8080",
		"control: 0",
		"controller: {auth: mtls}",
		"mode: default-deny",
		"logging: {audit_path: " + filepath.Join(dir, "audit.jsonl") + "}",
		"policy:",
		"  include:",
		"    - " + rulesPath,
		"llm:",
		"  enabled: false", // <-- disabled in YAML
		"  provider: anthropic",
		"  endpoint: https://example.invalid",
		"  timeout_seconds: 2",
		"",
	}, "\n")
	mustWrite(t, cfgPath, body)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{
		Output: advisor.Output{Effect: "allow", Confidence: "high", Reason: "ok"},
	}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath, "--check-llm"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, stdout.String())
	}
	out := stdout.String()
	if strings.Contains(out, "skipped (llm.enabled: false)") {
		t.Errorf("--check-llm did not override skip; got:\n%s", out)
	}
	for _, want := range []string{"OK (provider=anthropic", "effect=allow", "confidence=high"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestDoctor_CheckLLMFlag_WithEnabledTrueIsNoop: --check-llm
// combined with llm.enabled=true runs the LLM step exactly once
// (does not double-run). Pins that the flag and the config setting
// converge on the same single execution.
func TestDoctor_CheckLLMFlag_WithEnabledTrueIsNoop(t *testing.T) {
	cfgPath := minimalDoctorYaml(t, true)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{
		Output: advisor.Output{Effect: "allow", Confidence: "high", Reason: "ok"},
	}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath, "--check-llm"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, stdout.String())
	}
	out := stdout.String()
	// The wire call is announced exactly once via the "contacting
	// provider=" line; double-execution would print it twice.
	if got := strings.Count(out, "contacting provider="); got != 1 {
		t.Errorf("doctor announced LLM contact %d times with --check-llm + enabled=true; want exactly 1\n%s", got, out)
	}
	if got := strings.Count(out, "OK (provider="); got != 1 {
		t.Errorf("doctor reported OK %d times; want exactly 1\n%s", got, out)
	}
}

// TestDoctor_CheckLLMFlag_EmptyLLMBlockFailsEarly: --check-llm
// against a yaml whose llm block has no provider/endpoint set must
// fail early with a clear "set provider and endpoint" message, not
// attempt a wire call against an empty endpoint (closes #82).
func TestDoctor_CheckLLMFlag_EmptyLLMBlockFailsEarly(t *testing.T) {
	// minimalDoctorYaml(false) leaves llm with enabled: false and
	// no provider/endpoint. With --check-llm that yaml now reaches
	// the LLM step and must fail with the new pre-validation.
	cfgPath := minimalDoctorYaml(t, false)

	prev := doctorAdvisor
	defer func() { doctorAdvisor = prev }()
	doctorAdvisor = &advisor.MockProvider{Err: errors.New("advisor should not have been called")}

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"-c", cfgPath, "--check-llm"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute: expected error for empty llm block + --check-llm; got success\n%s", stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{"llm:", "FAIL", "llm.provider and llm.endpoint must both be set"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "contacting provider=") {
		t.Errorf("doctor reached the wire call despite empty llm block; got:\n%s", out)
	}
}

func TestDoctor_BadYaml_ReturnsConfigErr(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	mustWrite(t, cfgPath, "proxy: lo:8080\nmode: nonsense\n")

	var stdout bytes.Buffer
	cmd := newDoctorCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"-c", cfgPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute: expected error for invalid mode")
	}
	var ce *configErr
	if !errors.As(err, &ce) {
		t.Errorf("expected configErr, got %T: %v", err, err)
	}
	if !strings.Contains(stdout.String(), "config:") || !strings.Contains(stdout.String(), "FAIL") {
		t.Errorf("doctor should have printed config FAIL line; got:\n%s", stdout.String())
	}
}
