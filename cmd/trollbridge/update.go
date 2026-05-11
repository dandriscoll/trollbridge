package main

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

// updateGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch without cross-compiling. Production callers leave it
// at runtime.GOOS.
var updateGOOS = runtime.GOOS

// updateRunner executes the installer pipeline and streams its output
// to stdout/stderr. Replaced in tests with a recorder so the
// shell-out path can be exercised without touching the network or the
// filesystem.
var updateRunner = func(stdout, stderr io.Writer) error {
	c := exec.Command("sh", "-c", "curl -fsSL https://trollbridge.dev/install.sh | sh")
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update trollbridge to the latest release.",
		Long: `Runs the trollbridge.dev installer to fetch the latest released
binary for this host's OS and architecture, verify it against the
release SHA256SUMS, and install it over the current binary.

Mimics:

    curl -fsSL https://trollbridge.dev/install.sh | sh

If the binary lives in a privileged location (typically
/usr/local/bin), the installer prompts for sudo. Auto-update is not
yet supported on Windows; download the latest release from
https://github.com/dandriscoll/trollbridge/releases/latest.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if updateGOOS == "windows" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"Auto-update is not yet supported on Windows.")
				fmt.Fprintln(cmd.OutOrStdout(),
					"Download the latest release from https://github.com/dandriscoll/trollbridge/releases/latest")
				return nil
			}
			if err := updateRunner(cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return &runtimeErr{fmt.Errorf("update: %w", err)}
			}
			return nil
		},
	}
}
