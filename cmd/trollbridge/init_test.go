package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestInitWritesOnlyTrollbridgeYaml asserts that `trollbridge init`
// writes exactly one file (trollbridge.yaml) into the target dir.
// Job 053: rules.yaml stub no longer ships in the default install.
func TestInitWritesOnlyTrollbridgeYaml(t *testing.T) {
	dir := t.TempDir()

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "trollbridge.yaml" {
		t.Fatalf("expected only trollbridge.yaml; got %v", names)
	}
}

// TestInitDefaultHasNoIdentitiesOrPolicy asserts the parsed default
// config carries an empty identities slice and an empty policy
// include list. Job 053: trim unmotivated defaults from init output.
func TestInitDefaultHasNoIdentitiesOrPolicy(t *testing.T) {
	dir := t.TempDir()

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	cfg, err := config.Load(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if len(cfg.Identities) != 0 {
		t.Errorf("expected no identities in default config; got %d: %+v", len(cfg.Identities), cfg.Identities)
	}
	if len(cfg.Policy.Include) != 0 {
		t.Errorf("expected no policy.include in default config; got %v", cfg.Policy.Include)
	}

	body, err := os.ReadFile(filepath.Join(dir, "trollbridge.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, banned := range []string{"identities:", "policy:", "rules.yaml"} {
		if strings.Contains(string(body), banned) {
			t.Errorf("default config still contains %q; expected it removed", banned)
		}
	}
}
