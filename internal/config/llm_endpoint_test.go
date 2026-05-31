package config

import (
	"strings"
	"testing"
)

// TestCheckLLMEndpoint is the pure, deterministic table test for the
// llm.endpoint policy: reject unparseable endpoints and
// cleartext-http to a non-private host; warn (don't reject) on a
// private/loopback target so a legitimate local LLM advisor keeps
// working; allow public https silently.
func TestCheckLLMEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
		wantWarn bool
	}{
		{"public https ok", "https://api.anthropic.com/v1/messages", false, false},
		{"public https azure ok", "https://aoai-x.openai.azure.com/openai/deployments/x", false, false},
		{"public http rejected", "http://api.example.com/v1", true, false},
		{"public ip http rejected", "http://203.0.113.5:8080/v1", true, false},
		{"public ip https ok", "https://203.0.113.5/v1", false, false},
		{"loopback http warns", "http://127.0.0.1:11434/v1", false, true},
		{"loopback name http rejected", "http://localhost:11434/v1", true, false}, // "localhost" is a hostname, not a literal IP — not classified private without DNS
		{"ipv6 loopback https warns", "https://[::1]:8443/v1", false, true},
		{"rfc1918 http warns", "http://10.0.0.5:11434/v1", false, true},
		{"rfc1918 192 http warns", "http://192.168.1.10/v1", false, true},
		{"link-local http warns", "http://169.254.10.1/v1", false, true},
		{"unspecified https warns", "https://0.0.0.0:11434/v1", false, true},
		{"bad scheme rejected", "ftp://example.com/x", true, false},
		{"file scheme rejected", "file:///etc/passwd", true, false},
		{"no host rejected", "https:///v1", true, false},
		{"garbage rejected", "://nope", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := checkLLMEndpoint(tc.endpoint)
			if tc.wantErr && err == nil {
				t.Fatalf("checkLLMEndpoint(%q) = no error, want error", tc.endpoint)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkLLMEndpoint(%q) = error %v, want none", tc.endpoint, err)
			}
			if tc.wantWarn && warn == "" {
				t.Errorf("checkLLMEndpoint(%q) = no warn, want a private-address warning", tc.endpoint)
			}
			if !tc.wantWarn && !tc.wantErr && warn != "" {
				t.Errorf("checkLLMEndpoint(%q) = warn %q, want none", tc.endpoint, warn)
			}
		})
	}
}

// TestLoad_LLMEndpointRejectedAtLoad confirms validate() wires the fatal
// branch: a cleartext-http advisor to a public host fails to load.
func TestLoad_LLMEndpointRejectedAtLoad(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
llm:
  enabled: true
  endpoint: http://api.evil.example.com/v1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load to reject a cleartext-http public llm.endpoint; got nil")
	}
	if !strings.Contains(err.Error(), "llm.endpoint") {
		t.Errorf("error should name llm.endpoint; got: %v", err)
	}
}

// TestLoad_LLMEndpointPublicHTTPSLoads confirms a normal public https
// advisor loads cleanly (no false positive).
func TestLoad_LLMEndpointPublicHTTPSLoads(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
llm:
  enabled: true
  endpoint: https://api.anthropic.com/v1/messages
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("public https endpoint should load; got: %v", err)
	}
}

// TestLoad_LLMEndpointLocalAdvisorLoads confirms the warn-not-reject
// posture: a local http advisor (loopback) loads (it only warns), so a
// privacy-conscious operator's local LLM is not broken by the fix.
func TestLoad_LLMEndpointLocalAdvisorLoads(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
llm:
  enabled: true
  endpoint: http://127.0.0.1:11434/v1/chat
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("loopback http advisor should load (warn only); got: %v", err)
	}
}

// TestLoad_LLMEndpointSkippedWhenDisabled confirms the check is gated on
// llm.enabled — a disabled advisor with a junk endpoint still loads.
func TestLoad_LLMEndpointSkippedWhenDisabled(t *testing.T) {
	path := writeYaml(t, `proxy: lo:8080
control: lo:8081
controller: {auth: mtls}
mode: default-deny
logging: {audit_path: /tmp/a.jsonl}
llm:
  enabled: false
  endpoint: http://api.evil.example.com/v1
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("disabled llm should skip endpoint validation; got: %v", err)
	}
}
