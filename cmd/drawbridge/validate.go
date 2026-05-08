package main

import (
	"fmt"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/hostlist"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration and rule set.",
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
			allow, err := hostlist.LoadInline("allow", "drawbridge.yaml:lists.allow", cfg.Lists.Allow)
			if err != nil {
				return &configErr{err}
			}
			deny, err := hostlist.LoadInline("deny", "drawbridge.yaml:lists.deny", cfg.Lists.Deny)
			if err != nil {
				return &configErr{err}
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"drawbridge validate: OK\n"+
					"  config:    %s\n"+
					"  mode:      %s\n"+
					"  allowlist: %d patterns\n"+
					"  denylist:  %d patterns\n"+
					"  rules:     %d (version %s)\n"+
					"  known modifiers: %v\n",
				configPath, cfg.Mode,
				len(allow.Patterns), len(deny.Patterns),
				len(engine.Rules()), engine.RuleSetVersion(),
				policy.Phase1KnownModifiers())
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	return cmd
}
