package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwatch"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/generalize"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/server"
)

// TestReloadAfterInternalWrite_RefreshesSuggestionView reproduces #183: after a
// generalize suggestion is accepted (configwrite removes the sources and adds
// the wildcard), the daemon's internal-write reload must refresh the cfg the
// suggestion engine reads via srv.Cfg(). If the reload only refreshes the
// matcher (the pre-fix bug), the next detector pass scans the stale lists and
// re-offers the same generalization — the reported symptom.
//
// This exercises the run.go wiring (which server methods the reload helper
// calls), the layer the prior unit-level fixes (#173/#177) all passed at while
// the bug shipped. Closes the test gap filed in jobs 214/215.
func TestReloadAfterInternalWrite_RefreshesSuggestionView(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")

	cfgYAML := `proxy: lo:18080
control: 0
metrics: 0
mode: default-deny
lists:
  allow:
    - GET https://api.example.com/v1/users/1
    - GET https://api.example.com/v1/users/2
  deny: []
logging:
  audit_path: ` + auditPath + `
  operational_path: stderr
approvals:
  timeout_seconds: 5
  on_timeout: deny
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	eng, err := policy.NewEngine(string(cfg.Mode), nil, nil)
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	srv, err := server.New(cfg, eng)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	// #199: release the audit-log file handle before t.TempDir's
	// RemoveAll runs on cleanup. On Windows, an open file blocks
	// the temp-dir deletion and the test fails on cleanup.
	t.Cleanup(func() { _ = srv.Close() })
	if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
		t.Fatalf("SetLists: %v", err)
	}

	// The exact read path the suggestion engine uses (run.go wiring).
	lists := listsAdapter{cfgGetter: srv.Cfg}

	// Sanity: the detector offers a url_segment generalization over the two
	// concrete users before accept.
	allow, deny, _ := lists.CurrentLists()
	before := generalize.DetectAll(allow, deny)
	if len(before) == 0 {
		t.Fatalf("expected a generalization candidate before accept; got none (allow=%v)", allow)
	}
	cand := before[0]

	// Accept: configwrite removes the sources and adds the wildcard pattern,
	// exactly as suggestion.Manager.Accept / console.AcceptGeneralization do.
	if _, err := configwrite.Generalize(cfgPath, cand.List, cand.SuggestedPattern, cand.SourceEntries); err != nil {
		t.Fatalf("configwrite.Generalize: %v", err)
	}

	// The internal-write reload the daemon runs after its own write.
	w := configwatch.New(cfgPath)
	if err := reloadAfterInternalWrite(srv, cfgPath, w, slog.Default()); err != nil {
		t.Fatalf("reloadAfterInternalWrite: %v", err)
	}

	// The suggestion engine reads via srv.Cfg(): it must now see the cleaned
	// lists, so the accepted candidate is NOT re-offered.
	allow2, deny2, _ := lists.CurrentLists()
	for _, c := range allow2 {
		if c == cand.SourceEntries[0] {
			t.Errorf("source %q still visible to the suggestion engine after accept+reload; "+
				"srv.Cfg() is stale (allow=%v)", cand.SourceEntries[0], allow2)
		}
	}
	after := generalize.DetectAll(allow2, deny2)
	for _, c := range after {
		if c.SuggestedPattern == cand.SuggestedPattern && c.List == cand.List {
			t.Errorf("accepted generalization %q re-offered after accept+reload (#183 recurrence); "+
				"post-reload allow=%v", cand.SuggestedPattern, allow2)
		}
	}
}
