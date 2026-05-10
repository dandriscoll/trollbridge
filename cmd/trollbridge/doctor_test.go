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
	if !strings.Contains(out, "config:") || !strings.Contains(out, "OK (/") {
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
