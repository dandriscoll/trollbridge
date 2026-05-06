package main

import (
	"fmt"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and inspect rules.",
	}
	cmd.AddCommand(newRulesListCmd(), newRulesReloadCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print loaded rules with their priorities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			engine, err := policy.NewEngine(
				cfg.Mode,
				cfg.ResolveIncludePaths(configPath),
				policy.Phase1KnownModifiers(),
			)
			if err != nil {
				return &configErr{err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "rules version: %s  (mode: %s)\n", engine.RuleSetVersion(), cfg.Mode)
			for _, r := range engine.Rules() {
				fmt.Fprintf(out, "  [%4d] %-30s  effect=%-8s  match=%s\n",
					r.Priority, r.ID, r.Effect, summarizeMatch(r.Match))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	return cmd
}

func summarizeMatch(m policy.Match) string {
	parts := []string{}
	if len(m.Host) > 0 {
		parts = append(parts, fmt.Sprintf("host=%v", []string(m.Host)))
	}
	if len(m.Method) > 0 {
		parts = append(parts, fmt.Sprintf("method=%v", []string(m.Method)))
	}
	if m.Path != "" {
		parts = append(parts, fmt.Sprintf("path=%s", m.Path))
	}
	if m.Identity != "" {
		parts = append(parts, fmt.Sprintf("identity=%s", m.Identity))
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

func newRulesReloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Re-read rule files in the running process (sends SIGHUP).",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(),
				"drawbridge rules reload: send SIGHUP to the running drawbridge process to reload rules.\n",
				"  e.g.,  pkill -HUP drawbridge")
			return nil
		},
	}
	return cmd
}
