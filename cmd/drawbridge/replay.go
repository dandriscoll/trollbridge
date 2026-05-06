package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/types"
	"github.com/spf13/cobra"
)

// replay command lives under `drawbridge logs replay`.
func newLogsReplayCmd() *cobra.Command {
	var configPath, rulesPath string
	var since time.Duration
	var verbose bool
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Re-run past decisions against a new rule set; report diffs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			if rulesPath == "" {
				return &configErr{fmt.Errorf("--rules <file> is required")}
			}

			// Build a candidate engine using the new rules
			// stand-alone. This does NOT touch the active rule set
			// in the running drawbridge.
			engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
			if err != nil {
				return &configErr{err}
			}

			f, err := os.Open(cfg.Logging.AuditPath)
			if err != nil {
				return &runtimeErr{err}
			}
			defer f.Close()

			cutoff := time.Time{}
			if since > 0 {
				cutoff = time.Now().Add(-since)
			}

			counts := map[string]int{
				"unchanged":   0,
				"flip_to_allow": 0,
				"flip_to_deny":  0,
				"flip_other":    0,
				"unparseable":   0,
			}
			out := cmd.OutOrStdout()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				var e audit.Entry
				if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
					counts["unparseable"]++
					continue
				}
				ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
				if !cutoff.IsZero() && ts.Before(cutoff) {
					continue
				}

				req := &types.RequestEvent{
					ID:         e.RequestID,
					SessionID:  e.SessionID,
					IdentityID: e.IdentityID,
					Timestamp:  ts,
					Method:     e.Method,
					Scheme:     e.Scheme,
					Host:       e.Host,
					Port:       e.Port,
					Path:       e.Path,
					Headers:    http.Header{}, // headers not stored
					ClientAddr: e.ClientAddr,
				}
				newD := engine.Decide(req)
				oldEffect := e.Decision
				newEffect := string(newD.Effect)
				if oldEffect == newEffect {
					counts["unchanged"]++
				} else if newEffect == "allow" || newEffect == "ask_user_resolved_allow" {
					counts["flip_to_allow"]++
					if verbose {
						fmt.Fprintf(out, "%s  %s → %s  %s:%d%s  (rule=%s)\n",
							e.Timestamp, oldEffect, newEffect, e.Host, e.Port, e.Path, newD.RuleID)
					}
				} else if newEffect == "deny" || newEffect == "ask_user_resolved_deny" || newEffect == "ask_user_timed_out" {
					counts["flip_to_deny"]++
					if verbose {
						fmt.Fprintf(out, "%s  %s → %s  %s:%d%s  (rule=%s)\n",
							e.Timestamp, oldEffect, newEffect, e.Host, e.Port, e.Path, newD.RuleID)
					}
				} else {
					counts["flip_other"]++
				}
			}
			if err := sc.Err(); err != nil {
				return &runtimeErr{err}
			}

			fmt.Fprintln(out, "drawbridge logs replay: report")
			fmt.Fprintf(out, "  rules version: %s\n", engine.RuleSetVersion())
			fmt.Fprintf(out, "  unchanged:     %d\n", counts["unchanged"])
			fmt.Fprintf(out, "  flipped allow: %d\n", counts["flip_to_allow"])
			fmt.Fprintf(out, "  flipped deny:  %d\n", counts["flip_to_deny"])
			fmt.Fprintf(out, "  flipped other: %d\n", counts["flip_other"])
			fmt.Fprintf(out, "  unparseable:   %d\n", counts["unparseable"])
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "rule file to replay against (required)")
	cmd.Flags().DurationVar(&since, "since", 0, "only replay entries newer than this duration (e.g. 24h)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print each flipped decision")
	return cmd
}
