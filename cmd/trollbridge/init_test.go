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

// TestInit_DefaultDirMatchesXDGConfigPath is the regression guard for
// issue #8: `trollbridge init` (no -d) used to write to cwd while
// every other subcommand reads from defaultConfigPath() — operators
// who ran `init` then `doctor` without -c hit "no such file" because
// the two halves disagreed. After the fix init's default -d matches
// dirname(defaultConfigPath()).
func TestInit_DefaultDirMatchesXDGConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("TROLLBRIDGE_CONFIG", "")

	// Run init from a different cwd to prove the file does NOT land
	// in cwd just because the operator was sitting there.
	cwd := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	wantPath := filepath.Join(home, ".config", "trollbridge", "trollbridge.yaml")
	if _, err := os.Stat(wantPath); err != nil {
		t.Errorf("init should default to %s; not found: %v\noutput:\n%s", wantPath, err, out.String())
	}
	if _, err := os.Stat(filepath.Join(cwd, "trollbridge.yaml")); err == nil {
		t.Errorf("init must not leak into cwd when -d is omitted")
	}
}

// TestInit_TROLLBRIDGE_CONFIG_OverridesDefaultDir asserts that
// $TROLLBRIDGE_CONFIG flows into the default -d via filepath.Dir,
// matching the discovery path every other subcommand uses.
func TestInit_TROLLBRIDGE_CONFIG_OverridesDefaultDir(t *testing.T) {
	target := t.TempDir()
	override := filepath.Join(target, "trollbridge.yaml")
	t.Setenv("TROLLBRIDGE_CONFIG", override)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	if _, err := os.Stat(override); err != nil {
		t.Errorf("init should have written to %s (the dir component of $TROLLBRIDGE_CONFIG); not found: %v", override, err)
	}
}

// TestInit_NextStepsOmitsCWhenDefaultPath asserts the printed
// next-steps drops `-c <path>` arguments when the resolved file is
// at defaultConfigPath() — operators reading the printed advice
// don't have to copy a redundant flag.
func TestInit_NextStepsOmitsCWhenDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("TROLLBRIDGE_CONFIG", "")

	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	if strings.Contains(out.String(), "-c ") {
		t.Errorf("next-steps should not include `-c` when the file lives at defaultConfigPath; got:\n%s", out.String())
	}
	for _, want := range []string{"trollbridge doctor", "trollbridge run", "trollbridge validate"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("next-steps missing %q in:\n%s", want, out.String())
		}
	}
}

// TestInit_NextStepsIncludesAbsCWhenExplicitDir asserts that an
// explicit -d <other> threads an absolute -c <abs> through every
// follow-on so the printed advice survives a `cd` to anywhere.
func TestInit_NextStepsIncludesAbsCWhenExplicitDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("TROLLBRIDGE_CONFIG", "")

	other := t.TempDir()
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-d", other})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}

	wantC := "-c " + filepath.Join(other, "trollbridge.yaml")
	if !strings.Contains(out.String(), wantC) {
		t.Errorf("explicit -d should produce %q in the next-steps; got:\n%s", wantC, out.String())
	}
}
