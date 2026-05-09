package main

import (
	"os"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestQuickstartConfigYAML_DisablesControllerToAvoidCAReq closes
// issue #17: quickstart's flavor of the default config must disable
// the controller, otherwise the proxy daemon requires a CA at
// startup (controller mTLS dependency) — and CA generation in
// daemon-mode requires sudo, which contradicts the "30-second
// start" goal of the user-mode flow quickstart targets.
func TestQuickstartConfigYAML_DisablesControllerToAvoidCAReq(t *testing.T) {
	body := quickstartConfigYAML("/tmp/work")
	if !strings.Contains(body, "control: 0") {
		t.Errorf("quickstart default config should have `control: 0`; got:\n%s", body)
	}
	if strings.Contains(body, "control: lo:8081") {
		t.Errorf("quickstart default config should NOT enable the controller; got:\n%s", body)
	}
}

// TestQuickstartConfigYAML_AnchorsPathsAtInitDir asserts the
// user-mode invariant: every proxy-host path in the rendered yaml
// is anchored at the absolute init dir, not at /etc/trollbridge or
// /var/log/trollbridge.
func TestQuickstartConfigYAML_AnchorsPathsAtInitDir(t *testing.T) {
	body := quickstartConfigYAML("/tmp/work")
	for _, want := range []string{
		"cert_path: /tmp/work/trollbridge-ca.crt",
		"key_path:  /tmp/work/trollbridge-ca.key",
		"audit_path:        /tmp/work/trollbridge.audit.jsonl",
		"api_key_path: /tmp/work/llm.key",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in quickstart yaml:\n%s", want, body)
		}
	}
	for _, banned := range []string{
		"/etc/trollbridge/trollbridge-ca.crt",
		"/etc/trollbridge/llm.key",
		"/var/log/trollbridge/audit.jsonl",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("quickstart user-mode yaml should not reference daemon path %q:\n%s", banned, body)
		}
	}
}

// TestQuickstartConfigYAML_ParsesAsValidConfig asserts the body
// quickstart writes parses cleanly via config.Load.
func TestQuickstartConfigYAML_ParsesAsValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/trollbridge.yaml"
	body := quickstartConfigYAML(dir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load failed on quickstart yaml: %v\nbody:\n%s", err, body)
	}
	if !cfg.Control.Disabled() {
		t.Errorf("loaded cfg.Control should be disabled in quickstart")
	}
	if string(cfg.Mode) == "" {
		t.Errorf("quickstart yaml lost the mode field")
	}
}
