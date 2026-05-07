package main

import (
	"os"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/tui"
	"github.com/spf13/cobra"
)

func newTUICmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Approve or deny held requests interactively in real time.",
		Long: `Open a terminal UI that lists currently-held requests from the
running drawbridge daemon and lets you approve or deny each with a
single keystroke. Refreshes automatically as the queue changes.

Keys:
  a   approve the highlighted hold (scope: once)
  d   deny the highlighted hold
  ↑↓  or k/j       move selection
  r   refresh now
  q / Esc / Ctrl-C  quit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			if err := tui.RunApprovals(cmd.Context(), cfg, os.Stdin, os.Stdout); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
	return cmd
}
