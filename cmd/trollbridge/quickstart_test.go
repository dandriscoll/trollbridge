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
// startup (controller mTLS dependency) — and CA generation requires
// root, which contradicts the "30-second start" goal.
func TestQuickstartConfigYAML_DisablesControllerToAvoidCAReq(t *testing.T) {
	body := quickstartConfigYAML()
	if !strings.Contains(body, "control: 0") {
		t.Errorf("quickstart default config should have `control: 0`; got:\n%s", body)
	}
	if strings.Contains(body, "control: lo:8081") {
		t.Errorf("quickstart default config should NOT enable the controller; got:\n%s", body)
	}
}

// TestQuickstartConfigYAML_ParsesAsValidConfig asserts the body
// quickstart writes parses cleanly via config.Load. Uses a tmp file
// because config.Load takes a path (it resolves include files
// relative to the path's directory).
func TestQuickstartConfigYAML_ParsesAsValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/trollbridge.yaml"
	body := quickstartConfigYAML()
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

