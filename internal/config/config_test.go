package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeYaml(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "drawbridge.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_V2Minimal(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
adapter: lo
ports: {proxy: 8080, control: 8081}
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Adapter != "lo" {
		t.Errorf("Adapter = %q, want lo", cfg.Adapter)
	}
	if cfg.Ports.Proxy != 8080 || cfg.Ports.Control != 8081 {
		t.Errorf("ports = %+v, want {Proxy:8080 Control:8081}", cfg.Ports)
	}
	if cfg.BindHost() != "127.0.0.1" {
		t.Errorf("BindHost = %q, want 127.0.0.1 for adapter=lo", cfg.BindHost())
	}
	if got := cfg.BindAddr(8080); got != "127.0.0.1:8080" {
		t.Errorf("BindAddr = %q, want 127.0.0.1:8080", got)
	}
}

func TestLoad_V1RejectedWithMigrationMessage(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 1
listen: {address: 127.0.0.1, port: 8080}
mode: default-deny
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: expected error for v1 config; got nil")
	}
	msg := err.Error()
	for _, want := range []string{"version 1", "no longer supported", "drawbridge_version: 2", "adapter", "ports"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q in:\n%s", want, msg)
		}
	}
}

func TestLoad_AdapterAndPortsApplyDefaults(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Adapter != "lo" {
		t.Errorf("default Adapter = %q, want lo", cfg.Adapter)
	}
	if cfg.Ports.Proxy != 8080 {
		t.Errorf("default Ports.Proxy = %d, want 8080", cfg.Ports.Proxy)
	}
	if cfg.Ports.Control != 0 {
		t.Errorf("default Ports.Control = %d, want 0 (operator must opt in via init.go default or explicit setting)", cfg.Ports.Control)
	}
}

func TestLoad_ControlPortDisabledWith0(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
adapter: lo
ports: {proxy: 8080, control: 0}
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Ports.Control != 0 {
		t.Errorf("ports.control = %d, want 0 (disabled)", cfg.Ports.Control)
	}
}

func TestLoad_RejectsControllerAuthOtherThanMtls(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
adapter: lo
ports: {proxy: 8080, control: 8081}
controller: {auth: bearer}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-mtls controller auth")
	}
	if !strings.Contains(err.Error(), "controller.auth") {
		t.Errorf("error should name controller.auth: %v", err)
	}
}

func TestBindAddr_IPv6IsBracketed(t *testing.T) {
	cfg := &Config{Adapter: "fd00::1"}
	if got := cfg.BindAddr(8080); got != "[fd00::1]:8080" {
		t.Errorf("BindAddr = %q, want [fd00::1]:8080", got)
	}
}

func TestLoad_ListsParsedInline(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
adapter: lo
ports: {proxy: 8080, control: 8081}
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
lists:
  allow:
    - localhost
    - 127.0.0.1
  deny:
    - 169.254.169.254
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Lists.Allow) != 2 {
		t.Errorf("Lists.Allow len = %d, want 2: %v", len(cfg.Lists.Allow), cfg.Lists.Allow)
	}
	if len(cfg.Lists.Deny) != 1 {
		t.Errorf("Lists.Deny len = %d, want 1: %v", len(cfg.Lists.Deny), cfg.Lists.Deny)
	}
}
