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
	path := filepath.Join(dir, "trollbridge.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Minimal(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
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
	path := writeYaml(t, `proxy: all:8080
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
	path := writeYaml(t, `proxy: all:8080
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

func TestLoad_AppliesDefaults(t *testing.T) {
	path := writeYaml(t, `controller: {auth: mtls}
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
	path := writeYaml(t, `proxy: lo:8080
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
	path := writeYaml(t, `proxy: lo:8080
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

// TestLoad_LLMModeValidation pins the #54 contract: llm.mode must be
// either "review" or "research" (or empty, defaulting to review).
// Other values fail at config-load time with a message naming the
// valid set.
func TestLoad_LLMModeValidation(t *testing.T) {
	t.Run("review accepted", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
llm: {mode: review}
logging: {audit_path: /tmp/a.jsonl}
`)
		if _, err := Load(path); err != nil {
			t.Errorf("review mode rejected: %v", err)
		}
	})
	t.Run("research accepted", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
llm: {mode: research}
logging: {audit_path: /tmp/a.jsonl}
`)
		if _, err := Load(path); err != nil {
			t.Errorf("research mode rejected: %v", err)
		}
	})
	t.Run("empty defaults to review", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("default-mode load failed: %v", err)
		}
		if cfg.LLM.Mode != "review" {
			t.Errorf("default mode = %q, want review", cfg.LLM.Mode)
		}
	})
	t.Run("invalid value rejected", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
llm: {mode: bogus}
logging: {audit_path: /tmp/a.jsonl}
`)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid llm.mode")
		}
		if !strings.Contains(err.Error(), "llm.mode") {
			t.Errorf("error should name llm.mode: %v", err)
		}
		if !strings.Contains(err.Error(), "review") || !strings.Contains(err.Error(), "research") {
			t.Errorf("error should name valid set (review/research): %v", err)
		}
	})
}

// TestLoad_AuditLevelValidation pins the #113 contract:
// logging.audit_level must be one of `none`, `decisions`, `all`
// (or empty, defaulting to `all` for backwards compatibility).
// Unknown values fail at config-load time with a message naming
// the valid set.
func TestLoad_AuditLevelValidation(t *testing.T) {
	t.Run("empty defaults to all", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("default load failed: %v", err)
		}
		if cfg.Logging.AuditLevel != "all" {
			t.Errorf("default audit_level = %q, want all", cfg.Logging.AuditLevel)
		}
	})
	for _, accepted := range []string{"none", "decisions", "all"} {
		t.Run(accepted+" accepted", func(t *testing.T) {
			path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl, audit_level: `+accepted+`}
`)
			cfg, err := Load(path)
			if err != nil {
				t.Errorf("%q rejected: %v", accepted, err)
			}
			if cfg != nil && cfg.Logging.AuditLevel != accepted {
				t.Errorf("audit_level = %q, want %q", cfg.Logging.AuditLevel, accepted)
			}
		})
	}
	t.Run("invalid value rejected", func(t *testing.T) {
		path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl, audit_level: bogus}
`)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid audit_level")
		}
		if !strings.Contains(err.Error(), "logging.audit_level") {
			t.Errorf("error should name logging.audit_level: %v", err)
		}
		for _, want := range []string{"none", "decisions", "all"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name valid value %q: %v", want, err)
			}
		}
	})
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
	path := writeYaml(t, `proxy: lo:8080
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
	path := writeYaml(t, `proxy:   all:8080
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
	path := writeYaml(t, `proxy: 0
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
	path := writeYaml(t, `proxy: lo:8080
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

// TestLoad_FileNotFound_NamesInitCommand closes issue #27: when
// the config file does not exist, the error names `trollbridge
// init` (and `trollbridge quickstart`) inline so the operator's
// next step is well-defined without reading source.
func TestLoad_FileNotFound_NamesInitCommand(t *testing.T) {
	_, err := Load("/nonexistent/trollbridge.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	for _, want := range []string{
		"/nonexistent/trollbridge.yaml",
		"trollbridge init",
		"trollbridge quickstart",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in error: %v", want, err)
		}
	}
}

// TestTUIAlerts_ChimeDefaultsOn pins #72's default: operators get
// the chime unless they explicitly mute via `tui.alerts.chime: false`.
func TestTUIAlerts_ChimeDefaultsOn(t *testing.T) {
	var a TUIAlerts // zero value — Chime is nil
	if !a.ChimeEnabled() {
		t.Error("zero TUIAlerts: ChimeEnabled = false, want true")
	}
}

func TestTUIAlerts_ChimeExplicitFalseTurnsOff(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
tui:
  alerts:
    chime: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TUI.Alerts.ChimeEnabled() {
		t.Error("tui.alerts.chime=false: ChimeEnabled() = true, want false")
	}
}

func TestTUIAlerts_ChimeExplicitTrueIsOn(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
tui:
  alerts:
    chime: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TUI.Alerts.ChimeEnabled() {
		t.Error("tui.alerts.chime=true: ChimeEnabled() = false, want true")
	}
}

// TestLoad_RejectsUnknownTopLevelKey closes issue #123: an unknown
// top-level YAML key (here the dev-era `trollbridge_version`, dropped
// from the schema in e38ee83) must fail the load loudly, not be
// silently discarded. Before strict decoding this config loaded with
// no error and `trollbridge validate` reported OK.
func TestLoad_RejectsUnknownTopLevelKey(t *testing.T) {
	path := writeYaml(t, `trollbridge_version: 3
proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown top-level key `trollbridge_version`")
	}
	if !strings.Contains(err.Error(), "trollbridge_version") {
		t.Errorf("error should name the offending key `trollbridge_version`: %v", err)
	}
}

// TestLoad_RejectsUnknownNestedKey proves strict decoding reaches
// nested structs, not just the top level — a typo'd key inside the
// `llm` block must fail the same way (#123).
func TestLoad_RejectsUnknownNestedKey(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
llm:
  enabled: true
  provdier: anthropic
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown nested key `llm.provdier`")
	}
	if !strings.Contains(err.Error(), "provdier") {
		t.Errorf("error should name the offending key `provdier`: %v", err)
	}
}

// TestLoad_EmptyAndCommentsOnlyConfigUsesDefaults guards the io.EOF
// handling in the strict decoder: yaml.Decoder.Decode returns io.EOF
// on an empty or comments-only document where yaml.Unmarshal returned
// the zero value with no error. The load must still succeed — the
// zero Config flows through applyDefaults() (which fills in the
// default proxy bind) and validate() — not abort with a bare `EOF`
// parse error (#123 regression guard).
func TestLoad_EmptyAndCommentsOnlyConfigUsesDefaults(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"comments-only": "# just a comment\n# and another\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeYaml(t, body)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("empty config must load on defaults, not abort: %v", err)
			}
			if cfg.Proxy.Host != "127.0.0.1" || cfg.Proxy.Port != 8080 {
				t.Errorf("empty config: Proxy = %+v, want default 127.0.0.1:8080", cfg.Proxy)
			}
		})
	}
}

// TestLoad_RejectsMultipleDocuments closes issue #126: a config file
// with a `---`-separated second YAML document had documents 2..N
// silently ignored — the same silent-drop class as #123, at document
// granularity. The load must now reject the file.
func TestLoad_RejectsMultipleDocuments(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
---
proxy: lo:9999
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for multi-document config")
	}
	if !strings.Contains(err.Error(), "multiple") {
		t.Errorf("error should mention multiple documents: %v", err)
	}
}

// TestLoad_RejectsDocumentAfterEmptyDocument pins that the
// trailing-document scan (#126) does not stop at the first empty
// document — a real document after an empty one must still be
// caught. A single non-looping check would let this through.
func TestLoad_RejectsDocumentAfterEmptyDocument(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
---
---
proxy: lo:9999
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error: a real document follows an empty one")
	}
	if !strings.Contains(err.Error(), "multiple") {
		t.Errorf("error should mention multiple documents: %v", err)
	}
}

// TestLoad_TrailingSeparatorOK pins that a single document followed
// by a bare `---` separator with no content is not treated as a
// second document (#126 — the rejection must fire on real trailing
// documents, not on a harmless trailing separator).
func TestLoad_TrailingSeparatorOK(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
---
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("single document with a bare trailing separator must load: %v", err)
	}
}

// TestLoad_ExampleConfigLoads_DefaultState is the default-state
// invariant for #123: the shipped config.example.yaml — the file
// operators copy — must still load under strict decoding with zero
// operator edits. A regression here means strict decoding broke the
// out-of-the-box config.
func TestLoad_ExampleConfigLoads_DefaultState(t *testing.T) {
	if _, err := Load("../../config.example.yaml"); err != nil {
		t.Fatalf("shipped config.example.yaml must load under strict decoding: %v", err)
	}
}
