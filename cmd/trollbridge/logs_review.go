package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/spf13/cobra"
)

// newLogsReviewCmd implements `trollbridge logs review` (#114): a
// focused chronological listing of audit-log entries whose decision
// source is a human (approval queue, including timeout) or the LLM
// advisor. Static-policy auto-decisions (rule, default, allowlist,
// denylist) are filtered out so the operator sees only the entries
// where active judgment occurred.
//
// Categorization is shared with the logging.audit_level=decisions
// filter (#113) — both call (DecisionSource).IsHumanOrLLM().
func newLogsReviewCmd() *cobra.Command {
	var configPath string
	var since time.Duration
	cmd := &cobra.Command{
		Use:   "review",
		Short: "List audit entries from human or LLM decisions, ordered by time.",
		Long: `Review prints, in chronological order, every audit-log entry whose
decision source is the LLM advisor or a human (approval queue,
including queue timeout). Each entry shows the timestamp, source
tag, effect, request shape, identity, and reason; LLM entries
additionally show the model, confidence, and input hash.

Static-policy auto-decisions (rule, default, allowlist, denylist)
are filtered out. Use ` + "`trollbridge decisions`" + ` or ` + "`trollbridge logs tail`" + ` for
the full audit stream.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			f, err := os.Open(cfg.Logging.AuditPath)
			if err != nil {
				return &runtimeErr{fmt.Errorf("open audit log %s: %w", cfg.Logging.AuditPath, err)}
			}
			defer f.Close()
			return reviewAudit(f, since, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().DurationVar(&since, "since", 0, "only show entries newer than this duration (e.g. 24h)")
	return cmd
}

// reviewAudit is the testable inner loop: read JSONL from r, filter
// by (DecisionSource).IsHumanOrLLM() and --since, sort by timestamp,
// emit a formatted listing to out.
func reviewAudit(r io.Reader, since time.Duration, out io.Writer) error {
	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}

	type record struct {
		entry audit.Entry
		ts    time.Time
	}
	var matches []record

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if !types.DecisionSource(e.DecisionSource).IsHumanOrLLM() {
			continue
		}
		ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		if !cutoff.IsZero() && ts.Before(cutoff) {
			continue
		}
		matches = append(matches, record{entry: e, ts: ts})
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].ts.Before(matches[j].ts)
	})

	for _, rec := range matches {
		emitReviewEntry(out, rec.entry)
	}
	return nil
}

// emitReviewEntry formats a single audit entry for the review
// listing. Header + reason + (LLM trace, when applicable).
func emitReviewEntry(out io.Writer, e audit.Entry) {
	tag := sourceTag(types.DecisionSource(e.DecisionSource))
	path := e.Path
	identity := e.IdentityID
	fmt.Fprintf(out, "%s  %-5s  %-6s  %s %s:%d%s  (%s)\n",
		e.Timestamp, tag, e.Decision, e.Method, e.Host, e.Port, path, identity)
	if e.Reason != "" {
		fmt.Fprintf(out, "  reason: %s\n", e.Reason)
	}
	if types.DecisionSource(e.DecisionSource) == types.SourceLLMAdvisor {
		fmt.Fprintf(out, "  llm: model=%s confidence=%s input_hash=%s\n",
			e.LLMAdvisorID, e.LLMConfidence, e.LLMInputHash)
	}
}

// sourceTag renders a DecisionSource as a compact column-aligned
// tag for the review listing. The mapping mirrors IsHumanOrLLM
// (only human/LLM sources reach this code).
func sourceTag(s types.DecisionSource) string {
	switch s {
	case types.SourceLLMAdvisor:
		return "llm"
	case types.SourceApprovalQueue, types.SourceApprovalTimeout:
		return "human"
	}
	return string(s)
}
