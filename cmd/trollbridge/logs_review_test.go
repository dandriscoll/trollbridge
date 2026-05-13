package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/types"
)

// writeJSONL serializes each entry to a single JSONL line for the
// fixture audit log under test.
func writeJSONL(t *testing.T, path string, entries []audit.Entry) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestReviewAudit_FiltersHumanAndLLMOrderedByTime pins the core
// contract of `trollbridge logs review` (#114): only human and LLM
// decisions appear; entries are sorted by timestamp ascending; the
// LLM trace line appears for LLM entries.
func TestReviewAudit_FiltersHumanAndLLMOrderedByTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Five entries, deliberately written in non-chronological order:
	// rule entry (filtered out), llm (later), approval_queue (earlier),
	// allowlist (filtered out), approval_timeout (middle).
	entries := []audit.Entry{
		{
			Timestamp:      "2026-05-13T10:00:00Z",
			RequestID:      "rule-1",
			DecisionSource: string(types.SourceRule),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/auto",
			IdentityID:     "alice",
			Reason:         "matched rule X",
		},
		{
			Timestamp:      "2026-05-13T12:00:00Z",
			RequestID:      "llm-1",
			DecisionSource: string(types.SourceLLMAdvisor),
			Decision:       "deny",
			Method:         "POST",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/llm",
			IdentityID:     "alice",
			Reason:         "the LLM said no",
			LLMAdvisorID:   "claude-opus-4-7",
			LLMConfidence:  "high",
			LLMInputHash:   "abc123",
		},
		{
			Timestamp:      "2026-05-13T11:00:00Z",
			RequestID:      "human-1",
			DecisionSource: string(types.SourceApprovalQueue),
			Decision:       "allow",
			Method:         "DELETE",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/human",
			IdentityID:     "bob",
			Reason:         "operator approved",
		},
		{
			Timestamp:      "2026-05-13T10:30:00Z",
			RequestID:      "allow-1",
			DecisionSource: string(types.SourceAllowList),
			Decision:       "allow",
			Method:         "GET",
			Host:           "localhost",
			Port:           80,
			Path:           "/",
			IdentityID:     "alice",
			Reason:         "in allowlist",
		},
		{
			Timestamp:      "2026-05-13T11:30:00Z",
			RequestID:      "timeout-1",
			DecisionSource: string(types.SourceApprovalTimeout),
			Decision:       "deny",
			Method:         "POST",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/timeout",
			IdentityID:     "carol",
			Reason:         "queue timeout fell to deny",
		},
	}
	writeJSONL(t, path, entries)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var out bytes.Buffer
	if err := reviewAudit(f, 0, &out); err != nil {
		t.Fatalf("reviewAudit: %v", err)
	}
	got := out.String()

	// Filter assertions: the two static-policy entries must not appear.
	for _, banned := range []string{"rule-1", "allow-1", "/auto", "in allowlist"} {
		if strings.Contains(got, banned) {
			t.Errorf("static-policy entry leaked into review output: %q present in:\n%s", banned, got)
		}
	}
	// Inclusion assertions: the three human/LLM entries must appear.
	for _, expected := range []string{"/llm", "/human", "/timeout", "the LLM said no", "operator approved", "queue timeout fell to deny"} {
		if !strings.Contains(got, expected) {
			t.Errorf("expected substring %q missing from review output:\n%s", expected, got)
		}
	}
	// LLM trace line: must contain the model + confidence + input_hash for the LLM entry.
	if !strings.Contains(got, "model=claude-opus-4-7 confidence=high input_hash=abc123") {
		t.Errorf("LLM trace line missing or malformed in:\n%s", got)
	}
	// Source tag column: every entry carries the appropriate tag.
	if !strings.Contains(got, "  llm  ") {
		t.Errorf("llm source tag missing in:\n%s", got)
	}
	if strings.Count(got, " human ") < 2 {
		t.Errorf("expected two human source tags (approval_queue + approval_timeout), got:\n%s", got)
	}

	// Chronological ordering: 11:00 (human-1) < 11:30 (timeout-1) < 12:00 (llm-1).
	humanIdx := strings.Index(got, "/human")
	timeoutIdx := strings.Index(got, "/timeout")
	llmIdx := strings.Index(got, "/llm")
	if !(humanIdx < timeoutIdx && timeoutIdx < llmIdx) {
		t.Errorf("ordering wrong: humanIdx=%d timeoutIdx=%d llmIdx=%d in:\n%s", humanIdx, timeoutIdx, llmIdx, got)
	}
}

// TestReviewAudit_EmptyReasonOmitsLine pins that an entry with an
// empty Reason field does not produce a `reason: ""` line.
func TestReviewAudit_EmptyReasonOmitsLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []audit.Entry{
		{
			Timestamp:      "2026-05-13T10:00:00Z",
			RequestID:      "noreason-1",
			DecisionSource: string(types.SourceApprovalQueue),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/empty",
			IdentityID:     "alice",
			Reason:         "",
		},
	})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var out bytes.Buffer
	if err := reviewAudit(f, 0, &out); err != nil {
		t.Fatalf("reviewAudit: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "/empty") {
		t.Fatalf("entry missing: %s", got)
	}
	if strings.Contains(got, "reason:") {
		t.Errorf("empty reason should omit the line entirely; got:\n%s", got)
	}
}

// TestReviewAudit_SinceFiltersOldEntries pins the --since cutoff:
// entries older than the cutoff drop from the listing.
func TestReviewAudit_SinceFiltersOldEntries(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	fresh := now.Add(-10 * time.Minute).Format(time.RFC3339Nano)

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeJSONL(t, path, []audit.Entry{
		{
			Timestamp:      old,
			RequestID:      "stale-1",
			DecisionSource: string(types.SourceApprovalQueue),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/stale",
			IdentityID:     "alice",
			Reason:         "old",
		},
		{
			Timestamp:      fresh,
			RequestID:      "fresh-1",
			DecisionSource: string(types.SourceLLMAdvisor),
			Decision:       "allow",
			Method:         "GET",
			Host:           "api.example.com",
			Port:           443,
			Path:           "/fresh",
			IdentityID:     "alice",
			Reason:         "new",
			LLMAdvisorID:   "claude",
			LLMConfidence:  "medium",
			LLMInputHash:   "x",
		},
	})

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var out bytes.Buffer
	if err := reviewAudit(f, time.Hour, &out); err != nil {
		t.Fatalf("reviewAudit: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "/stale") {
		t.Errorf("entry older than --since cutoff should be filtered out; got:\n%s", got)
	}
	if !strings.Contains(got, "/fresh") {
		t.Errorf("entry inside cutoff should appear; got:\n%s", got)
	}
}

// TestReviewAudit_MalformedLineSkipped pins that a JSONL line that
// fails to parse is silently skipped (matches the `decisions` and
// `replay` command behavior). The valid following line is still
// emitted.
func TestReviewAudit_MalformedLineSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	good := audit.Entry{
		Timestamp:      "2026-05-13T10:00:00Z",
		RequestID:      "good-1",
		DecisionSource: string(types.SourceLLMAdvisor),
		Decision:       "allow",
		Method:         "GET",
		Host:           "api.example.com",
		Port:           443,
		Path:           "/good",
		IdentityID:     "alice",
		Reason:         "ok",
		LLMAdvisorID:   "claude",
		LLMConfidence:  "high",
		LLMInputHash:   "h",
	}
	goodJSON, err := json.Marshal(&good)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("{not-json\n")
	body = append(body, goodJSON...)
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var out bytes.Buffer
	if err := reviewAudit(f, 0, &out); err != nil {
		t.Fatalf("reviewAudit: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "/good") {
		t.Errorf("valid entry after malformed line should be emitted; got:\n%s", got)
	}
}
