package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/dandriscoll/trollbridge/internal/updater"
	"github.com/spf13/cobra"
)

// updateGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch without cross-compiling. Production callers leave it
// at runtime.GOOS.
var updateGOOS = runtime.GOOS

func newUpdateCmd() *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update trollbridge to the latest release.",
		Long: `Runs the trollbridge.dev installer to fetch the latest released
binary for this host's OS and architecture, verify it against the
release SHA256SUMS, and install it to ~/.local/bin in user mode.

Mimics:

    curl -fsSL https://trollbridge.dev/install.sh | bash

Override the install directory with TROLLBRIDGE_INSTALL_DIR. Auto-update
is not yet supported on Windows; download the latest release from
https://github.com/dandriscoll/trollbridge/releases/latest.

Use --check to print the latest released version without invoking
the installer.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if checkOnly {
				latest, err := updater.CheckLatest()
				if err != nil {
					return &runtimeErr{fmt.Errorf("update --check: %w", err)}
				}
				current := server.Version
				cleanLatest := strings.TrimPrefix(latest, "v")
				cleanCurrent := strings.TrimPrefix(current, "v")
				cleanCurrent = strings.TrimSuffix(cleanCurrent, "-dev")
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "current: %s\n", current)
				fmt.Fprintf(out, "latest:  %s\n", latest)
				if cleanCurrent == cleanLatest {
					fmt.Fprintln(out, "you are up to date.")
				} else {
					fmt.Fprintf(out, "update available; run `trollbridge update` to install %s.\n", latest)
				}
				return nil
			}
			if updateGOOS == "windows" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"Auto-update is not yet supported on Windows.")
				fmt.Fprintln(cmd.OutOrStdout(),
					"Download the latest release from https://github.com/dandriscoll/trollbridge/releases/latest")
				return nil
			}
			if err := updater.Run(cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				// Surface the classified hint above the wrapped error
				// so the operator's first read names the next action,
				// not the curl/sh exit code.
				var ue *updater.Error
				if errors.As(err, &ue) {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"\ntrollbridge update failed (%s).\nhint: %s\n",
						ue.Class, ue.Hint)
				}
				return &runtimeErr{fmt.Errorf("update: %w", err)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"check for the latest release without installing; report current vs latest version")
	return cmd
}
