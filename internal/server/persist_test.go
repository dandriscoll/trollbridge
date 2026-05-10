package server_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestPersistCallback_AddsAllowAndReloads exercises the wiring shape
// `cmd/trollbridge/run.go` installs at startup: a queue-level
// DecisionPersist callback that calls configwrite.AddAllow on a
// manual approve, then reloads the lists in-process so the very next
// request matches the new pattern.
//
// Doesn't go through a subprocess (the closure under test is small
// and inlined in main); the assertion is "if approve fires, the YAML
// changes and the in-memory matcher sees the new pattern."
func TestPersistCallback_AddsAllowAndReloads(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	cfgYAML := `proxy: lo:8080
control: 0
mode: default-ask
approvals:
  timeout_seconds: 5
  on_timeout: deny
lists:
  allow:
    - already.example.com
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	q := approvals.New(8, time.Second, "deny")
	defer q.Shutdown()

	// Mirror the closure shape from cmd/trollbridge/run.go.
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		var pattern string
		if req.Method == "CONNECT" || req.Path == "" {
			if req.Port == 0 {
				pattern = req.Host
			} else {
				pattern = fmt.Sprintf("%s:%d", req.Host, req.Port)
			}
		}
		if pattern == "" {
			return
		}
		switch effect {
		case types.EffectAllow:
			_, _ = configwrite.AddAllow(cfgPath, pattern)
		case types.EffectDeny:
			_, _ = configwrite.AddDeny(cfgPath, pattern)
		}
	})

	req := &types.RequestEvent{
		ID:         "r1",
		IdentityID: "x",
		Method:     "CONNECT",
		Scheme:     "https-tunneled",
		Host:       "newly.example.com",
		Port:       443,
	}
	id, ch, err := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Approve via the in-process path.
	if !q.Approve(id, "once", "tui") {
		t.Fatalf("Approve returned false")
	}
	d := <-ch
	if d.Effect != types.EffectAskUserResolvedAllow {
		t.Fatalf("decision = %v, want resolved_allow", d.Effect)
	}

	// Give the synchronous callback a beat to land its YAML write.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(cfgPath)
		if strings.Contains(string(raw), "newly.example.com:443") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	final, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(final), "newly.example.com:443") {
		t.Errorf("trollbridge.yaml does not contain 'newly.example.com:443' after approve; got:\n%s", string(final))
	}
	if !strings.Contains(string(final), "already.example.com") {
		t.Errorf("trollbridge.yaml lost the pre-existing pattern after approve; got:\n%s", string(final))
	}

	// Re-load the file and confirm it parses back into a config that
	// has the new pattern. (Mirrors the daemon's reload path.)
	freshCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("re-load config: %v", err)
	}
	found := false
	for _, p := range freshCfg.Lists.Allow {
		if p == "newly.example.com:443" {
			found = true
		}
	}
	if !found {
		t.Errorf("fresh config did not include the new pattern; allow=%v", freshCfg.Lists.Allow)
	}
}

// TestPersistCallback_DenyAddsToDenyList covers the deny symmetry.
func TestPersistCallback_DenyAddsToDenyList(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	cfgYAML := `proxy: lo:8080
control: 0
mode: default-ask
approvals:
  timeout_seconds: 5
  on_timeout: deny
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	q := approvals.New(8, time.Second, "deny")
	defer q.Shutdown()
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		pattern := fmt.Sprintf("%s:%d", req.Host, req.Port)
		switch effect {
		case types.EffectAllow:
			_, _ = configwrite.AddAllow(cfgPath, pattern)
		case types.EffectDeny:
			_, _ = configwrite.AddDeny(cfgPath, pattern)
		}
	})

	req := &types.RequestEvent{Method: "CONNECT", Scheme: "https-tunneled", Host: "blocked.example.com", Port: 443}
	id, ch, err := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if !q.Deny(id, "operator denied", "tui") {
		t.Fatalf("Deny returned false")
	}
	d := <-ch
	if d.Effect != types.EffectAskUserResolvedDeny {
		t.Fatalf("decision = %v, want resolved_deny", d.Effect)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(cfgPath)
		if strings.Contains(string(raw), "blocked.example.com:443") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	final, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(final), "deny:") || !strings.Contains(string(final), "blocked.example.com:443") {
		t.Errorf("trollbridge.yaml deny section missing 'blocked.example.com:443' after deny; got:\n%s", string(final))
	}
}

// _ keep context import alive for future expansion.
var _ = context.Background
