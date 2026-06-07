package server_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/types"
)

// installPersistCallbackForTest mirrors the SetDecisionPersist
// shape from `cmd/trollbridge/run.go` (POST-#194 fix), including
// the consolidation step. Tests use this mirror because the real
// callback is closed over heavy state (server, opLog, reloader);
// the inline reproduction is the pre-existing convention in
// `persist_test.go`. The mirror MUST stay in sync with the real
// callback's reconcile logic — drift would invalidate the tests.
func installPersistCallbackForTest(t *testing.T, q *approvals.Queue, cfgPath string) {
	t.Helper()
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		if source == "llm-advisor" {
			return // mirrors #193 guard
		}
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
		// Route through the production primitive — drift between
		// this test mirror and the real cmd/trollbridge/run.go
		// callback is exactly the #179 → #194 recurrence shape.
		switch effect {
		case types.EffectAllow:
			_, _, _, _ = configwrite.OperatorApprove(cfgPath, pattern)
		case types.EffectDeny:
			_, _, _, _ = configwrite.OperatorDeny(cfgPath, pattern)
		}
	})
}

// readYAMLLists returns the (allow, deny) pattern lists from the
// YAML file, parsed loosely (looks for `lists.allow:` and
// `lists.deny:` sections and reads `- foo` bullets under each).
// Sufficient for asserting on the consolidation invariant — the
// production YAML round-trip is exercised by configwrite's own tests.
func readYAMLLists(t *testing.T, path string) (allow, deny []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	section := ""
	for _, ln := range lines {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "allow:") {
			section = "allow"
			continue
		}
		if strings.HasPrefix(trim, "deny:") {
			section = "deny"
			continue
		}
		if strings.HasPrefix(trim, "- ") {
			val := strings.TrimSpace(strings.TrimPrefix(trim, "- "))
			val = strings.TrimSpace(strings.Trim(val, `"'`))
			switch section {
			case "allow":
				allow = append(allow, val)
			case "deny":
				deny = append(deny, val)
			}
		}
	}
	return
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestPersistCallback_ApprovingDeniedURLRemovesItFromDeny is the
// load-bearing #194 regression test: a URL on the deny list,
// approved via the operator-approval persist callback, must end
// up ONLY on allow — never on both.
//
// This is the recurrence of #179. Prior to the fix in this job,
// the callback wrote to allow without removing from deny; the
// next request still hit deny (deny wins) and the operator's
// approve was silently no-op'd.
//
// Fixture discipline (insight #40 / job 142 I2): the URL is on
// deny pre-action, so a buggy callback that just calls AddAllow
// leaves it on both lists — visible in the post-assertion.
func TestPersistCallback_ApprovingDeniedURLRemovesItFromDeny(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	cfgYAML := `proxy: lo:8080
control: 0
mode: default-ask
approvals:
  timeout_seconds: 5
  on_timeout: deny
lists:
  allow: []
  deny:
    - blocked.example.com:443
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	q := approvals.New(8, time.Second, "deny")
	defer q.Shutdown()
	installPersistCallbackForTest(t, q, cfgPath)

	req := &types.RequestEvent{
		ID:         "r1",
		IdentityID: "x",
		Method:     "CONNECT",
		Scheme:     "https-tunneled",
		Host:       "blocked.example.com",
		Port:       443,
	}
	id, ch, _, err := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if !q.Approve(id, "rule-1", "tui") {
		t.Fatal("Approve returned false unexpectedly")
	}
	<-ch

	allow, deny := readYAMLLists(t, cfgPath)
	pattern := "blocked.example.com:443"
	if !contains(allow, pattern) {
		t.Errorf("after operator approve: pattern %q not on allow list; allow=%v deny=%v", pattern, allow, deny)
	}
	if contains(deny, pattern) {
		t.Errorf("after operator approve: pattern %q STILL on deny list (recurrence of #179); allow=%v deny=%v", pattern, allow, deny)
	}
}

// TestPersistCallback_DenyingApprovedURLRemovesItFromAllow is the
// symmetric direction (closes #194): a URL on allow, denied via
// the operator-approval persist callback, must end up ONLY on
// deny.
func TestPersistCallback_DenyingApprovedURLRemovesItFromAllow(t *testing.T) {
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
    - approved.example.com:443
  deny: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	q := approvals.New(8, time.Second, "deny")
	defer q.Shutdown()
	installPersistCallbackForTest(t, q, cfgPath)

	req := &types.RequestEvent{
		ID:         "r1",
		IdentityID: "x",
		Method:     "CONNECT",
		Scheme:     "https-tunneled",
		Host:       "approved.example.com",
		Port:       443,
	}
	id, ch, _, err := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if !q.Deny(id, "operator denied", "tui") {
		t.Fatal("Deny returned false unexpectedly")
	}
	<-ch

	allow, deny := readYAMLLists(t, cfgPath)
	pattern := "approved.example.com:443"
	if !contains(deny, pattern) {
		t.Errorf("after operator deny: pattern %q not on deny list; allow=%v deny=%v", pattern, allow, deny)
	}
	if contains(allow, pattern) {
		t.Errorf("after operator deny: pattern %q STILL on allow list (recurrence of #179); allow=%v deny=%v", pattern, allow, deny)
	}
}

// TestListConsolidationInvariant_AcrossOperatorActionPaths is the
// SWEEP TEST the user demanded ("address the test and/or process
// gap as well as the bug"). For each known operator-action persist
// path, it runs both reconciliation directions and asserts the
// cross-list invariant: a URL is never on both lists after any
// single operator action.
//
// When a NEW operator-action persist path is added in the future
// (suggestion-engine accept, batch operator commands, attach-mode
// list edits via #189, etc.), add it to the table. If the new
// path doesn't reconcile, this test FAILS in CI before the new
// path can ship — closing the recurrence shape that produced
// #179 → #194.
//
// Per GO.md "Filed-but-unimplemented closures become mandatory on
// recurrence": prior job 221 (the #179 fix) did NOT file this
// sweep test. The recurrence demands it now.
func TestListConsolidationInvariant_AcrossOperatorActionPaths(t *testing.T) {
	type pathDriver func(t *testing.T, cfgPath string, list, pattern string)

	// Each entry drives ONE production code path that operator
	// actions take to persist allow/deny list changes. Each driver
	// MUST call into the real production primitive (not a parallel
	// copy) — drift between test and prod is exactly the recurrence
	// shape that produced #179 → #194.
	//
	// Adding a NEW operator-action persistence path? Add a driver
	// here that calls into the new path's load-bearing primitive.
	// If the new path does not consolidate, the corresponding
	// scenarios in this test will fail and block the PR.
	pathDrivers := map[string]pathDriver{
		// configwrite.OperatorApprove / OperatorDeny are the single
		// load-bearing primitive every operator-action persist path
		// MUST use. The daemon's SetDecisionPersist callback
		// (cmd/trollbridge/run.go) and the console Backend.addPattern
		// (internal/console/console.go) both call these. If either
		// caller stops routing through OperatorApprove/OperatorDeny,
		// the per-caller tests catch it; this sweep test catches
		// regressions in the primitive itself.
		"configwrite.OperatorApprove/OperatorDeny": func(t *testing.T, cfgPath, list, pattern string) {
			switch list {
			case "allow":
				_, _, _, _ = configwrite.OperatorApprove(cfgPath, pattern)
			case "deny":
				_, _, _, _ = configwrite.OperatorDeny(cfgPath, pattern)
			}
		},
	}

	scenarios := []struct {
		name        string
		seedAllow   []string
		seedDeny    []string
		actionList  string // "allow" or "deny"
		pattern     string
	}{
		{
			name:       "deny→allow consolidates",
			seedAllow:  nil,
			seedDeny:   []string{"x.example.com:443"},
			actionList: "allow",
			pattern:    "x.example.com:443",
		},
		{
			name:       "allow→deny consolidates",
			seedAllow:  []string{"x.example.com:443"},
			seedDeny:   nil,
			actionList: "deny",
			pattern:    "x.example.com:443",
		},
	}

	for driverName, driver := range pathDrivers {
		for _, sc := range scenarios {
			t.Run(driverName+"/"+sc.name, func(t *testing.T) {
				dir := t.TempDir()
				cfgPath := filepath.Join(dir, "trollbridge.yaml")
				yaml := "proxy: lo:8080\ncontrol: 0\nmode: default-ask\nlists:\n  allow:\n"
				for _, p := range sc.seedAllow {
					yaml += "    - " + p + "\n"
				}
				if len(sc.seedAllow) == 0 {
					yaml += "    []\n"
				}
				yaml += "  deny:\n"
				for _, p := range sc.seedDeny {
					yaml += "    - " + p + "\n"
				}
				if len(sc.seedDeny) == 0 {
					yaml += "    []\n"
				}
				if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
					t.Fatal(err)
				}

				driver(t, cfgPath, sc.actionList, sc.pattern)

				allow, deny := readYAMLLists(t, cfgPath)
				switch sc.actionList {
				case "allow":
					if !contains(allow, sc.pattern) {
						t.Errorf("post-action: pattern %q not on allow; allow=%v deny=%v", sc.pattern, allow, deny)
					}
					if contains(deny, sc.pattern) {
						t.Errorf("INVARIANT VIOLATED: pattern %q on BOTH allow and deny after action %q (#179/#194 recurrence shape)", sc.pattern, sc.actionList)
					}
				case "deny":
					if !contains(deny, sc.pattern) {
						t.Errorf("post-action: pattern %q not on deny; allow=%v deny=%v", sc.pattern, allow, deny)
					}
					if contains(allow, sc.pattern) {
						t.Errorf("INVARIANT VIOLATED: pattern %q on BOTH allow and deny after action %q (#179/#194 recurrence shape)", sc.pattern, sc.actionList)
					}
				}
			})
		}
	}
}
