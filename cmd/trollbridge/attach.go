package main

import (
	"os"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/tui"
	"github.com/spf13/cobra"
)

// newAttachCmd implements `trollbridge attach`: drive the same
// two-pane operator UI that `trollbridge run` shows on the proxy
// host, talking to the daemon over the mTLS control plane.
//
// Closes #37: the unified TUI lives in internal/tui; `run` mounts
// the local-only backend (allow/deny/test/doctor write to the daemon
// in-process), and `attach` mounts a remote backend that gates those
// commands with a one-line "not available in attach mode" hint until
// the control plane exposes them.
func newAttachCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach to a running trollbridge daemon and drive its operator UI.",
		Long: `Open the same two-pane operator UI that trollbridge run shows on
the proxy host, but driven over the daemon's mTLS control plane so
you can review and resolve held requests from another terminal.

The approvals pane works the same as on the proxy host. The console
pane is read-only for now: list editing, test, and doctor must run
on the proxy host where the config file lives.

Keys:
  Tab               switch between the approvals pane and the console
  a                 approve the highlighted hold (scope: once)
  d                 deny the highlighted hold
  ↑↓  or k/j        move selection in the approvals pane
  r                 refresh approvals now
  q / Esc           quit (when the approvals pane is focused)
  Ctrl-C            quit at any time`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			backend := &console.Backend{LocalOnly: false}
			if err := tui.RunOperator(cmd.Context(), tui.NewHTTPClient(cfg), os.Stdin, os.Stdout, backend, ""); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	return cmd
}
