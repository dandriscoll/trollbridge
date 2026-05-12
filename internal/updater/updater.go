// Package updater shells out to trollbridge.dev/install.sh to upgrade
// the local trollbridge binary in place. The CLI's `update` subcommand
// and the TUI console's `update` line both call Run.
package updater

import (
	"io"
	"os/exec"
)

// URL is the canonical install.sh location. Tests override it to point
// at a local httptest server; production callers leave it as-is.
var URL = "https://trollbridge.dev/install.sh"

// Pipeline returns the shell pipeline fed to `sh -c`. install.sh
// auto-bootstraps under bash with `exec bash "$0" "$@"`; when piped
// from dash (/bin/sh on Debian/Ubuntu), $0 is the dash binary path and
// bash refuses to execute a binary, aborting with exit 126. Pipe to
// bash directly so the bootstrap is a no-op (closes #94).
func Pipeline() string {
	return "curl -fsSL " + URL + " | bash"
}

// Run executes the installer pipeline, streaming stdout/stderr to the
// caller's writers. Replaced in tests with a recorder so callers can
// exercise their wiring without touching the network.
var Run = func(stdout, stderr io.Writer) error {
	c := exec.Command("sh", "-c", Pipeline())
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}
