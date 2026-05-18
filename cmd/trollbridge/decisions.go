package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/spf13/cobra"
)

func newDecisionsCmd() *cobra.Command {
	var configPath string
	var since time.Duration
	var pending bool
	cmd := &cobra.Command{
		Use:   "decisions",
		Short: "Show recent proxy decisions from the audit log.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			if pending {
				body, err := controlclient.Get(cfg, "/v1/holds")
				if err != nil {
					return &runtimeErr{err}
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			cutoff := time.Now().Add(-since)
			// Align with the live audit_level setting (#167): when
			// the daemon was configured to filter to `decisions` or
			// `none`, an operator reviewing the log via this CLI
			// should not be shown entries the running config would
			// have filtered out (e.g. legacy static-policy entries
			// from a prior run with audit_level=all).
			lvl, lvlErr := audit.ParseLevel(cfg.Logging.AuditLevel)
			if lvlErr != nil {
				// Validator already accepted this at config-load;
				// fail closed on unexpected parse drift.
				return &runtimeErr{fmt.Errorf("parse audit_level %q: %w", cfg.Logging.AuditLevel, lvlErr)}
			}
			f, err := os.Open(cfg.Logging.AuditPath)
			if err != nil {
				return &runtimeErr{fmt.Errorf("open audit log %s: %w", cfg.Logging.AuditPath, err)}
			}
			defer f.Close()
			out := cmd.OutOrStdout()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				var e audit.Entry
				if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
					continue
				}
				// Apply the live audit_level filter (#167 part c).
				switch lvl {
				case audit.LevelNone:
					continue
				case audit.LevelDecisions:
					if !types.DecisionSource(e.DecisionSource).IsHumanOrLLM() {
						continue
					}
				}
				ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
				if since > 0 && ts.Before(cutoff) {
					continue
				}
				path := e.Path
				if path == "" {
					path = "(no path; CONNECT)"
				}
				fmt.Fprintf(out, "%s  %-6s  %-30s  %s:%d%s  reason=%q\n",
					e.Timestamp, e.Decision, e.IdentityID, e.Host, e.Port, path, e.Reason)
			}
			return scanner.Err()
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().DurationVar(&since, "since", 0, "only show entries newer than this duration (e.g. 1h)")
	cmd.Flags().BoolVar(&pending, "pending", false, "show pending approval-queue entries (Phase 2)")
	return cmd
}
