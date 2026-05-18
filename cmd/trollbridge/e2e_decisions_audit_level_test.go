//go:build e2e

// E2E for `trollbridge decisions` audit_level alignment (#167
// part c). When audit_level=decisions, the CLI's listing must
// filter out pre-existing static-policy entries on disk — not
// just rely on the daemon having filtered them at write time. A
// pre-existing audit file from a prior run with audit_level=all
// can still contain static-policy entries; this CLI lane must
// honor the live setting.

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

func TestE2E_Decisions_AuditLevelAligned(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	entries := []audit.Entry{
		{Timestamp: "2026-05-18T10:00:00Z", RequestID: "rule-1", DecisionSource: string(types.SourceRule), Decision: "allow", Host: "api.example.com", Port: 443, Path: "/static-rule", IdentityID: "alice", Reason: "matched rule"},
		{Timestamp: "2026-05-18T10:10:00Z", RequestID: "llm-1", DecisionSource: string(types.SourceLLMAdvisor), Decision: "deny", Host: "api.example.com", Port: 443, Path: "/llm-decision", IdentityID: "alice", Reason: "advisor flagged"},
		{Timestamp: "2026-05-18T10:20:00Z", RequestID: "queue-1", DecisionSource: string(types.SourceApprovalQueue), Decision: "allow", Host: "api.example.com", Port: 443, Path: "/human-decision", IdentityID: "bob", Reason: "operator approved"},
		{Timestamp: "2026-05-18T10:30:00Z", RequestID: "allow-1", DecisionSource: string(types.SourceAllowList), Decision: "allow", Host: "api.example.com", Port: 443, Path: "/static-allowlist", IdentityID: "alice", Reason: "in allowlist"},
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

	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	yaml := "proxy: lo:8080\ncontrol: 0\nmode: default-deny\nlogging:\n  audit_path: " + auditPath + "\n  operational_path: stderr\n  audit_level: decisions\n"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e2eBinary, "decisions", "--config", yamlPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("trollbridge decisions failed: %v\n%s", err, out)
	}
	got := string(out)

	// Static-policy entries must NOT appear under audit_level=decisions.
	for _, banned := range []string{"static-rule", "static-allowlist", "in allowlist", "matched rule"} {
		if strings.Contains(got, banned) {
			t.Errorf("audit_level=decisions leaked static-policy entry %q in decisions CLI output:\n%s", banned, got)
		}
	}
	// Human + LLM entries must appear.
	for _, want := range []string{"llm-decision", "human-decision", "advisor flagged", "operator approved"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected substring %q missing from decisions output:\n%s", want, got)
		}
	}
}
