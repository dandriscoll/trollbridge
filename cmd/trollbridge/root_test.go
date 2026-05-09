package main

import "testing"

// TestDefaultConfigPath_CwdWhenNoEnv asserts that defaultConfigPath
// no longer falls back to $XDG_CONFIG_HOME/$HOME — the cwd-relative
// path is the only resolution when TROLLBRIDGE_CONFIG is unset.
// trollbridge is a deployed proxy, not a user application; its
// config does not belong in the user's XDG tree.
func TestDefaultConfigPath_CwdWhenNoEnv(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	got := defaultConfigPath()
	if got != "trollbridge.yaml" {
		t.Errorf("defaultConfigPath() = %q, want %q (XDG/$HOME must not participate)", got, "trollbridge.yaml")
	}
}

// TestDefaultConfigPath_TROLLBRIDGE_CONFIG_Wins keeps the env-var
// override (used by the systemd unit and any operator who deliberately
// places the config outside cwd).
func TestDefaultConfigPath_TROLLBRIDGE_CONFIG_Wins(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONFIG", "/etc/trollbridge/trollbridge.yaml")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	got := defaultConfigPath()
	if got != "/etc/trollbridge/trollbridge.yaml" {
		t.Errorf("defaultConfigPath() = %q, want %q", got, "/etc/trollbridge/trollbridge.yaml")
	}
}
