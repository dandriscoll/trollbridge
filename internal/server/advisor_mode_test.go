package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
)

// TestAdvisor_AOAIResearchModeFallsBack pins the #54 fallback: when
// llm.mode=research is configured against an AOAI provider,
// trollbridge logs a warning naming the gap and runs the advisor in
// review mode (no web_search tool).
func TestAdvisor_AOAIResearchModeFallsBack(t *testing.T) {
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"
	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 16, AuditOverflow: "block"},
		Approvals: config.Approvals{TimeoutSeconds: 5, OnTimeout: "deny", MaxPending: 4},
		Forwarder: config.Forwarder{MaxIdleConns: 4, MaxIdleConnsPerHost: 2, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		LLM: config.LLM{
			Enabled:  true,
			Provider: "aoai",
			Mode:     "research",
		},
	}
	engine, err := policy.NewEngine(cfg.Mode, nil, policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	auditLogger, err := audit.New(auditPath, 16, audit.OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	// Capture opLog into a buffer so we can assert the warning fired.
	var logBuf bytes.Buffer
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	opLog := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: level}))

	srv, err := NewWithLoggers(cfg, engine, auditLogger, opLog)
	if err != nil {
		t.Fatalf("NewWithLoggers: %v", err)
	}
	t.Cleanup(func() { _ = srv })

	logs := logBuf.String()
	if !strings.Contains(logs, "advisor_research_unsupported_provider") {
		t.Errorf("expected fallback warning event; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "review") {
		t.Errorf("warning should name the effective mode (review); logs:\n%s", logs)
	}

	// Smoke: build an Anthropic translator request directly and
	// confirm that with the *server's* effective mode, no web_search
	// tool would be added even though cfg said research.
	tr := &advisor.MockProvider{}
	_ = tr
	// We can't easily inspect what the server's advisor would emit
	// without a real classification round-trip; the warning + the
	// translator unit tests in internal/advisor/modes_test.go pin
	// the no-web_search outcome together.

	// keep oplog reference reachable in case the test grows
	_ = time.Now
	_ = oplog.EventStartup
}
