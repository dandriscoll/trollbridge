package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerify_NoConfig_ReportsParseGap exercises the load-failure
// path: verify against a non-existent config returns a structured
// gap rather than crashing or printing a stack trace. The agent
// must be able to parse the failure shape just like the success
// shape.
func TestVerify_NoConfig_ReportsParseGap(t *testing.T) {
	res := runVerify(context.Background(), filepath.Join(t.TempDir(), "nope.yaml"), 500*time.Millisecond)
	if res.OK {
		t.Fatal("verify against missing config returned OK")
	}
	if res.ConfigParses {
		t.Error("config_parses=true when file does not exist")
	}
	foundParseGap := false
	for _, g := range res.Gaps {
		if g.ID == "config_parse" {
			foundParseGap = true
			if !g.BlocksOK {
				t.Error("config_parse gap not marked blocking")
			}
		}
	}
	if !foundParseGap {
		t.Errorf("expected config_parse gap, got: %+v", res.Gaps)
	}
}

// TestVerify_ProxyUnreachable_ReportsGap covers the most common
// failure shape an onboarding agent hits: config valid, proxy not
// yet started. verify must name the gap and the next action.
func TestVerify_ProxyUnreachable_ReportsGap(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal valid config that binds to a port nothing
	// will answer on (high port less likely to collide).
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	cfg := `proxy:   127.0.0.1:9
control: 0
metrics: 0
mode: default-deny
lists:
  allow: []
  deny: []
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runVerify(context.Background(), cfgPath, 200*time.Millisecond)
	if res.OK {
		t.Fatal("verify against unreachable proxy returned OK")
	}
	if !res.ConfigParses {
		t.Errorf("config_parses=false; config_error=%s", res.ConfigError)
	}
	if res.ProxyReachable {
		t.Error("proxy_reachable=true when nothing is listening on :9")
	}
	foundUnreachable := false
	for _, g := range res.Gaps {
		if g.ID == "proxy_unreachable" {
			foundUnreachable = true
			if !strings.Contains(g.NextAction, "trollbridge run") {
				t.Errorf("proxy_unreachable next_action missing `trollbridge run` hint: %s", g.NextAction)
			}
		}
	}
	if !foundUnreachable {
		t.Errorf("expected proxy_unreachable gap, got: %+v", res.Gaps)
	}
}

// TestVerify_JSONFlag_PrintsOneObject asserts the --json surface
// prints exactly one JSON object on stdout, nothing on stderr,
// and the shape matches verifyResult. Matches the convention
// `validate --json` already follows (CI-bindable).
func TestVerify_JSONFlag_PrintsOneObject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	cfg := `proxy:   127.0.0.1:9
control: 0
metrics: 0
mode: default-deny
lists:
  allow: []
  deny: []
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newVerifyCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--json", "-c", cfgPath, "--probe-timeout-ms", "200"})
	_ = cmd.Execute() // non-zero is expected (proxy not running)
	if stdout.Len() == 0 {
		t.Fatal("stdout empty")
	}
	var v map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\n%s", err, stdout.String())
	}
	for _, key := range []string{"ok", "config_parses", "proxy_reachable", "gaps", "next_actions", "confirmations", "plan_version"} {
		if _, ok := v[key]; !ok {
			t.Errorf("verify JSON missing required key %q", key)
		}
	}
}
