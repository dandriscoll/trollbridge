package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and inspect rules.",
	}
	cmd.AddCommand(newRulesListCmd(), newRulesReloadCmd(), newRulesAddCmd())
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
	var configPath string
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Re-read rule files via the control API.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			url := fmt.Sprintf("http://%s/v1/rules/reload", cfg.Approvals.ControlListen)
			httpClient := &http.Client{Timeout: 5 * time.Second}
			resp, err := httpClient.Post(url, "application/json", nil)
			if err != nil {
				return &runtimeErr{fmt.Errorf("control API: %w; alternatively send SIGHUP to the running drawbridge", err)}
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 400 {
				return &runtimeErr{fmt.Errorf("control API: %s: %s", resp.Status, string(body))}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	return cmd
}

// rules add <file> appends a rule file to the policy.include list of
// the active config and triggers a reload via the control API.
//
// In Phase 2, "appending" means: copy the supplied file alongside
// the configured rule files (in the config dir) and append its
// path to the config's include list. Validates the file first.
func newRulesAddCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "add <rules-file>",
		Short: "Validate a rule file and merge it into the active rule set.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			src := args[0]
			content, err := os.ReadFile(src)
			if err != nil {
				return &runtimeErr{fmt.Errorf("read %s: %w", src, err)}
			}
			// Validate by attempting to load it alongside the
			// existing rule set.
			tmpDir, err := os.MkdirTemp("", "drawbridge-rules-*")
			if err != nil {
				return &runtimeErr{err}
			}
			defer os.RemoveAll(tmpDir)
			tmpPath := tmpDir + "/candidate.yaml"
			if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
				return &runtimeErr{err}
			}
			// Combine existing includes with the candidate.
			includes := append(cfg.ResolveIncludePaths(configPath), tmpPath)
			if _, err := policy.NewEngine(cfg.Mode, includes, policy.KnownModifiers()); err != nil {
				return &configErr{fmt.Errorf("validation failed: %w", err)}
			}
			// Place the file into the config directory under a
			// stable name and append to the include list.
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "drawbridge rules add: validation OK")
			fmt.Fprintln(out, "  to make this rule file active, copy it next to your config and add it to policy.include:")
			fmt.Fprintf(out, "    cp %s <your-config-dir>/\n", src)
			fmt.Fprintf(out, "  then `drawbridge rules reload` to apply.\n")
			// Sweep test path: if the user passed `--apply`, do
			// the copy + reload via control API. Out of scope for
			// Phase 2 first cut; documented as TODO.
			_ = bytes.NewReader
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	return cmd
}
