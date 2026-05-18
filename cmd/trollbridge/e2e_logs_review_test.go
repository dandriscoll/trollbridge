//go:build e2e

// Subprocess e2e for `trollbridge logs review` (#162). The cobra
// wiring is unit-tested; this lane exercises the full path from
// fixture audit JSONL → binary subprocess → stdout filtering.
// A regression that includes static-policy entries in the review
// output ships through unit tests when reviewAudit's internal
// filtering is intact but the cobra wiring forgot to call it.

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestE2E_LogsReview_FiltersStaticPolicyEntries writes a fixture
// audit file containing a mix of human, LLM, and static-policy
// entries, runs `trollbridge logs review --config <fixture>` as a
// subprocess, and asserts stdout includes the human/LLM entries
// and excludes the static-policy ones.
func TestE2E_LogsReview_FiltersStaticPolicyEntries(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	entries := []audit.Entry{
		{
			Timestamp:      "2026-05-18T10:00:00Z",
			RequestID:      "rule-1",
			DecisionSource: string(types.SourceRule),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/static-policy-rule",
			IdentityID:     "alice",
			Reason:         "matched rule",
		},
		{
			Timestamp:      "2026-05-18T10:10:00Z",
			RequestID:      "allow-1",
			DecisionSource: string(types.SourceAllowList),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/static-policy-allowlist",
			IdentityID:     "alice",
			Reason:         "in allowlist",
		},
		{
			Timestamp:      "2026-05-18T10:20:00Z",
			RequestID:      "llm-1",
			DecisionSource: string(types.SourceLLMAdvisor),
			Decision:       "deny",
			Method:         "POST",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/llm-said-no",
			IdentityID:     "alice",
			Reason:         "advisor flagged",
			LLMAdvisorID:   "claude-opus-4-7",
			LLMConfidence:  "high",
			LLMInputHash:   "abc123",
		},
		{
			Timestamp:      "2026-05-18T10:30:00Z",
			RequestID:      "human-1",
			DecisionSource: string(types.SourceApprovalQueue),
			Decision:       "allow",
			Method:         "DELETE",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/operator-approved",
			IdentityID:     "bob",
			Reason:         "operator approved",
		},
	}

	f, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()

	// Minimal yaml that the CLI's config-load accepts; logs review
	// only reads `logging.audit_path`.
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	// Port 8080 is fine — the daemon isn't being started, only
	// `logs review` reads this config for the audit_path.
	yaml := "proxy: lo:8080\ncontrol: 0\nmode: default-deny\nlogging:\n  audit_path: " + auditPath + "\n  operational_path: stderr\n"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "logs", "review", "--config", yamlPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("trollbridge logs review failed: %v\n%s", err, out)
	}
	got := string(out)

	// Excluded: static-policy entries.
	for _, banned := range []string{"static-policy-rule", "static-policy-allowlist", "in allowlist"} {
		if strings.Contains(got, banned) {
			t.Errorf("static-policy entry leaked into review output: %q present in:\n%s", banned, got)
		}
	}
	// Included: human + LLM entries.
	for _, want := range []string{"llm-said-no", "advisor flagged", "operator-approved", "operator approved"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected substring %q missing from review output:\n%s", want, got)
		}
	}
}
