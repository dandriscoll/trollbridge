package main

import (
	"fmt"
	"runtime"

	"github.com/dandriscoll/trollbridge/internal/updater"
	"github.com/spf13/cobra"
)

// updateGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch without cross-compiling. Production callers leave it
// at runtime.GOOS.
var updateGOOS = runtime.GOOS

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update trollbridge to the latest release.",
		Long: `Runs the trollbridge.dev installer to fetch the latest released
binary for this host's OS and architecture, verify it against the
release SHA256SUMS, and install it to ~/.local/bin in user mode.

Mimics:

    curl -fsSL https://trollbridge.dev/install.sh | bash

Override the install directory with TROLLBRIDGE_INSTALL_DIR. Auto-update
is not yet supported on Windows; download the latest release from
https://github.com/dandriscoll/trollbridge/releases/latest.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if updateGOOS == "windows" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"Auto-update is not yet supported on Windows.")
				fmt.Fprintln(cmd.OutOrStdout(),
					"Download the latest release from https://github.com/dandriscoll/trollbridge/releases/latest")
				return nil
			}
			if err := updater.Run(cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return &runtimeErr{fmt.Errorf("update: %w", err)}
			}
			return nil
		},
	}
}
