package main

import (
	"fmt"
	"io"
	"os"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
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
			// Fail loudly to stderr *before* entering the TUI when
			// the mTLS client cert / key / CA cannot be loaded.
			// The TUI footer truncates long error messages at
			// terminal width, hiding both the path the binary
			// expected and the suggested fix command — so an
			// operator who hits this gets stuck staring at a
			// "load operator cert (/home/dan/.trollbridge/controlle…"
			// fragment with no way to dismiss or read more (#46).
			if err := controlclient.Preflight(cfg); err != nil {
				printAttachCertError(cmd.ErrOrStderr(), cfg, err)
				return &configErr{err}
			}
			backend := &console.Backend{
				LocalOnly: false,
				// #189: wire the remote list-writer so allow / deny
				// verbs in the attach-mode console call the proxy's
				// /v1/lists/allow + /deny endpoints instead of the
				// "not available in attach mode" stub.
				Remote: remoteListWriterClient{cfg: cfg},
			}
			// requestShutdown is nil: attach is a remote consumer-host
			// client that does not own the proxy daemon, so quitting the
			// TUI must not propagate a cancel anywhere.
			if err := tui.RunOperator(cmd.Context(), tui.NewHTTPClient(cfg), os.Stdin, os.Stdout, backend, "", nil, tui.Options{ChimeEnabled: cfg.TUI.Alerts.ChimeEnabled()}); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	return cmd
}

// printAttachCertError writes a multi-line, untruncated description
// of an mTLS preflight failure to stderr. Names the paths tried,
// whether each came from a TROLLBRIDGE_CONTROLLER_* env override or
// the default ~/.trollbridge/ location, and the operator's next
// steps. Operators see this in their normal shell — not in the
// TUI footer that would truncate at terminal width.
func printAttachCertError(out io.Writer, cfg *config.Config, cause error) {
	cert, key, ca, _ := controlclient.CertPaths(cfg)
	envSet := func(name string) string {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			return " (from $" + name + ")"
		}
		return ""
	}
	fmt.Fprintln(out, "trollbridge attach: cannot reach the control plane.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  cause:")
	fmt.Fprintf(out, "    %s\n", cause.Error())
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  paths tried:")
	fmt.Fprintf(out, "    cert: %s%s\n", cert, envSet("TROLLBRIDGE_CONTROLLER_CERT"))
	fmt.Fprintf(out, "    key:  %s%s\n", key, envSet("TROLLBRIDGE_CONTROLLER_KEY"))
	fmt.Fprintf(out, "    ca:   %s%s\n", ca, envSet("TROLLBRIDGE_CONTROLLER_CA"))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  fix:")
	fmt.Fprintln(out, "    1. On the proxy host, generate an operator client cert:")
	fmt.Fprintln(out, "         trollbridge ca client-cert <name>")
	fmt.Fprintln(out, "    2. Copy controller-client.crt and controller-client.key")
	fmt.Fprintln(out, "       into ~/.trollbridge/ on this host (or set the")
	fmt.Fprintln(out, "       TROLLBRIDGE_CONTROLLER_CERT/_KEY env vars).")
	fmt.Fprintln(out, "    3. Re-run `trollbridge attach`.")
}

// remoteListWriterClient implements console.RemoteListWriter by
// calling the proxy's /v1/lists/{allow,deny} endpoints over the
// existing mTLS-authenticated control plane (#189). The cfg
// carries the controller cert/key and base URL.
type remoteListWriterClient struct{ cfg *config.Config }

func (c remoteListWriterClient) AddAllow(pattern string) (bool, error) {
	return controlclient.ListEdit(c.cfg, "POST", "allow", pattern)
}
func (c remoteListWriterClient) AddDeny(pattern string) (bool, error) {
	return controlclient.ListEdit(c.cfg, "POST", "deny", pattern)
}
func (c remoteListWriterClient) RemoveAllow(pattern string) (bool, error) {
	return controlclient.ListEdit(c.cfg, "DELETE", "allow", pattern)
}
func (c remoteListWriterClient) RemoveDeny(pattern string) (bool, error) {
	return controlclient.ListEdit(c.cfg, "DELETE", "deny", pattern)
}
