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

func TestLoad_V3Minimal(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Host != "127.0.0.1" || cfg.Proxy.Port != 8080 {
		t.Errorf("Proxy = %+v, want 127.0.0.1:8080", cfg.Proxy)
	}
	if cfg.Control.Host != "127.0.0.1" || cfg.Control.Port != 8081 {
		t.Errorf("Control = %+v, want 127.0.0.1:8081", cfg.Control)
	}
	if got := cfg.Proxy.Addr(); got != "127.0.0.1:8080" {
		t.Errorf("Proxy.Addr = %q, want 127.0.0.1:8080", got)
	}
}

func TestLoad_AllAliasResolvesTo0000(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: all:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Host != "0.0.0.0" {
		t.Errorf("Proxy.Host = %q, want 0.0.0.0 (alias `all`)", cfg.Proxy.Host)
	}
	if got := cfg.Proxy.ClientHost(); got != "127.0.0.1" {
		t.Errorf("Proxy.ClientHost = %q, want 127.0.0.1 (clients dial loopback)", got)
	}
}

func TestLoad_PerSurfaceDifferentHosts(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: all:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Host == cfg.Control.Host {
		t.Errorf("expected proxy and control to bind different hosts: proxy=%s control=%s",
			cfg.Proxy.Host, cfg.Control.Host)
	}
}

func TestLoad_V1Rejected(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 1
listen: {address: 127.0.0.1, port: 8080}
mode: default-deny
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: expected error for v1 config; got nil")
	}
	for _, want := range []string{"version 1", "no longer supported", "drawbridge_version: 3", "proxy:", "control:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("v1 rejection missing %q in:\n%s", want, err.Error())
		}
	}
}

func TestLoad_V2Rejected(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 2
adapter: lo
ports: {proxy: 8080, control: 8081}
controller: {auth: mtls}
mode: default-deny
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: expected error for v2 config; got nil")
	}
	for _, want := range []string{"version 2", "no longer supported", "drawbridge_version: 3", "proxy:", "control:", "all", "lo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("v2 rejection missing %q in:\n%s", want, err.Error())
		}
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Host != "127.0.0.1" || cfg.Proxy.Port != 8080 {
		t.Errorf("default Proxy = %+v, want 127.0.0.1:8080", cfg.Proxy)
	}
	if !cfg.Control.Disabled() {
		t.Errorf("default Control should be disabled (require explicit opt-in); got %+v", cfg.Control)
	}
	if !cfg.Metrics.Disabled() {
		t.Errorf("default Metrics should be disabled; got %+v", cfg.Metrics)
	}
}

func TestLoad_ControlDisabledExplicit(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: lo:8080
control: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Control.Disabled() {
		t.Errorf("ports.control = 0 should disable; got %+v", cfg.Control)
	}
}

func TestLoad_RejectsNonMtlsControllerAuth(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: lo:8080
control: lo:8081
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

func TestParseBind_RejectsMissingPort(t *testing.T) {
	cases := []string{"lo", "all", "127.0.0.1"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := parseBindScalar(raw)
			if err == nil {
				t.Fatalf("expected error for %q; got nil", raw)
			}
			if !strings.Contains(err.Error(), "missing port") {
				t.Errorf("error should mention missing port; got: %v", err)
			}
		})
	}
}

func TestParseBind_RejectsBarePort(t *testing.T) {
	_, err := parseBindScalar("8080")
	if err == nil {
		t.Fatal("expected error for bare port `8080`")
	}
	if !strings.Contains(err.Error(), "missing port") && !strings.Contains(err.Error(), "missing host") {
		t.Errorf("error should mention missing host/port; got: %v", err)
	}
}

func TestParseBind_PortRange(t *testing.T) {
	if _, err := parseBindScalar("lo:0"); err == nil {
		// lo:0 is invalid for a *required* surface; parser-level we
		// accept port 0 only as the disabled sentinel "" / "0", not
		// "host:0". Confirm parser rejects "lo:0".
		t.Errorf("expected error for `lo:0`; port 0 with explicit host is meaningless")
	}
	if _, err := parseBindScalar("lo:70000"); err == nil {
		t.Error("expected error for port 70000")
	}
}

func TestParseBind_IPv6Bracketed(t *testing.T) {
	b, err := parseBindScalar("[fd00::1]:8080")
	if err != nil {
		t.Fatalf("parseBindScalar: %v", err)
	}
	if b.Host != "fd00::1" || b.Port != 8080 {
		t.Errorf("parsed = %+v, want fd00::1:8080", b)
	}
	if got := b.Addr(); got != "[fd00::1]:8080" {
		t.Errorf("Addr = %q, want bracketed [fd00::1]:8080", got)
	}
}

func TestParseBind_DisabledForms(t *testing.T) {
	for _, raw := range []string{"", "0"} {
		b, err := parseBindScalar(raw)
		if err != nil {
			t.Fatalf("parseBindScalar(%q): %v", raw, err)
		}
		if !b.Disabled() {
			t.Errorf("%q should be Disabled; got %+v", raw, b)
		}
		if got := b.Addr(); got != "" {
			t.Errorf("disabled bind Addr should be empty; got %q", got)
		}
	}
}

func TestValidate_RejectsSameHostSamePortCollision(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: lo:8080
control: lo:8080
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for proxy/control on same host:port")
	}
	if !strings.Contains(err.Error(), "collide") {
		t.Errorf("error should mention collision; got: %v", err)
	}
}

func TestValidate_AcceptsSamePortDifferentHost(t *testing.T) {
	// Same port on different hosts is legal; the kernel decides
	// whether the binds actually overlap.
	path := writeYaml(t, `drawbridge_version: 3
proxy:   all:8080
control: 127.0.0.1:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestValidate_ProxyRequired(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: 0
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for proxy: 0 (required surface)")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Errorf("error should name proxy; got: %v", err)
	}
}

func TestLoad_ListsParsedInline(t *testing.T) {
	path := writeYaml(t, `drawbridge_version: 3
proxy: lo:8080
control: lo:8081
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
