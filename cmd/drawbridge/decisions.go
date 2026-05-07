package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/controlclient"
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
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	cmd.Flags().DurationVar(&since, "since", 0, "only show entries newer than this duration (e.g. 1h)")
	cmd.Flags().BoolVar(&pending, "pending", false, "show pending approval-queue entries (Phase 2)")
	return cmd
}
