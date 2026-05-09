package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// newCAUninstallCmd is symmetric to `newCAInstallCmd`. Where
// `ca install` copies the trollbridge CA into the platform trust
// store and re-runs `update-ca-*`, `ca uninstall` reverses that
// step: removes the cert from the platform's drop-in directory
// and re-runs the trust-store rebuild. Issue #29.
//
// The same flag surface as `ca install`: --config / --cert (so
// the operator can name the cert file the platform-specific argv
// removes), --all-platforms (print every supported platform's
// commands), --apply (actually run them), --yes (skip the
// confirmation prompt).
//
// Per-platform argv tuples mirror installStepsFor's destinations.
// Symmetric error shapes: Windows / unknown-Linux fail with a
// platform-specific message instead of letting an empty plan
// fall through.
func newCAUninstallCmd() *cobra.Command {
	var configPath, certPath string
	var allPlatformsFlag, applyFlag, yesFlag bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Print (or, with --apply, run) the commands to remove the trollbridge CA from the system trust store.",
		Long: `Reverse of ` + "`trollbridge ca install`" + `: remove the trollbridge CA
cert from the platform-specific trust-store drop-in directory
and rebuild the trust store.

Cert resolution mirrors ` + "`ca install`" + `: --cert > --config's
interception.ca.cert_path > /etc/trollbridge/trollbridge-ca.crt >
/usr/local/share/ca-certificates/trollbridge-ca.crt. The resolved
path is informational — uninstall removes the platform's
*destination* file, not the source.

By default this prints the commands; --apply runs them. --apply
requires root.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgCert, _ := configCertPath(configPath)
			cp, err := findInstallCert(certPath, cfgCert, os.Stat)
			if err != nil {
				// uninstall is fine even if the source cert is no
				// longer present — the destination might still be in
				// the trust store. Use the canonical default name in
				// that case.
				cp = DefaultCACertPath
			}
			if abs, aerr := filepath.Abs(cp); aerr == nil {
				cp = abs
			}
			if applyFlag {
				return applyUninstall(
					cmd.OutOrStdout(),
					cmd.InOrStdin(),
					detectPlatform(),
					cp,
					yesFlag,
					execStepRunner{},
					func() bool { return os.Geteuid() == 0 },
				)
			}
			printUninstallHelp(cmd.OutOrStdout(), cp, allPlatformsFlag, detectPlatform())
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	cmd.Flags().StringVar(&certPath, "cert", "", "explicit cert path (informational; uninstall targets the platform's destination)")
	cmd.Flags().BoolVar(&allPlatformsFlag, "all-platforms", false, "print uninstall commands for every supported platform")
	cmd.Flags().BoolVar(&applyFlag, "apply", false, "execute the system trust-store uninstall (requires root)")
	cmd.Flags().BoolVar(&yesFlag, "yes", false, "with --apply: skip the confirmation prompt")
	return cmd
}

// uninstallStepsFor returns the argv tuples to remove the CA from
// the platform trust store. Mirrors installStepsFor's destinations:
// every install destination is a remove target.
func uninstallStepsFor(p platform) []installStep {
	switch p {
	case platformLinuxDebian, platformLinuxAlpine:
		const dst = "/usr/local/share/ca-certificates/trollbridge-ca.crt"
		return []installStep{
			{desc: "remove CA cert from " + dst, argv: []string{"rm", "-f", dst}},
			{desc: "rebuild system trust store (update-ca-certificates)", argv: []string{"update-ca-certificates", "--fresh"}},
		}
	case platformLinuxFedora:
		const dst = "/etc/pki/ca-trust/source/anchors/trollbridge-ca.crt"
		return []installStep{
			{desc: "remove CA cert from " + dst, argv: []string{"rm", "-f", dst}},
			{desc: "rebuild system trust store (update-ca-trust)", argv: []string{"update-ca-trust"}},
		}
	case platformLinuxArch:
		return []installStep{
			{desc: "remove CA cert from trust anchors", argv: []string{"trust", "anchor", "--remove", "trollbridge-ca"}},
		}
	case platformDarwin:
		return []installStep{
			{
				desc: "remove trollbridge CA from /Library/Keychains/System.keychain",
				argv: []string{"security", "delete-certificate", "-c", "trollbridge-ca", "/Library/Keychains/System.keychain"},
			},
		}
	default:
		return nil
	}
}

func uninstallCommandsFor(p platform, certPath string) []string {
	steps := uninstallStepsFor(p)
	if steps == nil {
		switch p {
		case platformWindows:
			return []string{
				"# run from an elevated (Administrator) PowerShell or cmd.exe:",
				`certutil -delstore -f "Root" trollbridge-ca`,
			}
		case platformLinuxUnknown:
			return []string{
				"# Linux distribution not auto-detected.",
				"# Try: sudo rm -f /usr/local/share/ca-certificates/trollbridge-ca.crt && sudo update-ca-certificates --fresh",
				"# Or:  sudo rm -f /etc/pki/ca-trust/source/anchors/trollbridge-ca.crt && sudo update-ca-trust",
			}
		default:
			return []string{
				"# OS not detected — see `trollbridge ca uninstall --all-platforms`.",
			}
		}
	}
	out := make([]string, 0, len(steps)*2)
	for _, s := range steps {
		out = append(out, "sudo "+strings.Join(s.argv, " "))
	}
	return out
}

func printUninstallHelp(out io.Writer, certPath string, allPlatformsFlag bool, detected platform) {
	fmt.Fprintf(out, "trollbridge CA uninstall: removing the cert installed at install-time from %s\n\n", certPath)
	platforms := []platform{detected}
	if allPlatformsFlag {
		platforms = allPlatforms
	}
	for _, p := range platforms {
		fmt.Fprintf(out, "== System trust store: %s ==\n", p.friendly())
		for _, line := range uninstallCommandsFor(p, certPath) {
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}
	if !allPlatformsFlag {
		fmt.Fprintln(out, "For other platforms: trollbridge ca uninstall --all-platforms")
	}
}

func applyUninstall(
	out io.Writer,
	in io.Reader,
	p platform,
	certPath string,
	yes bool,
	runner stepRunner,
	isPrivileged func() bool,
) error {
	switch p {
	case platformWindows:
		return &runtimeErr{fmt.Errorf("--apply is not supported on Windows; copy the certutil command from `trollbridge ca uninstall` and run it from an elevated (Administrator) shell")}
	case platformLinuxUnknown:
		return &runtimeErr{fmt.Errorf("--apply is not supported on this Linux distribution (auto-detection failed); re-run without --apply to see commands you can copy")}
	case platformUnknown:
		return &runtimeErr{fmt.Errorf("--apply is not supported on this OS; re-run without --apply to see the available platforms via --all-platforms")}
	}

	steps := uninstallStepsFor(p)
	if len(steps) == 0 {
		return &runtimeErr{fmt.Errorf("no --apply uninstall steps registered for platform %s", p)}
	}

	if !isPrivileged() {
		return &runtimeErr{fmt.Errorf("--apply requires root; rerun as: sudo %s", strings.Join(os.Args, " "))}
	}

	fmt.Fprintf(out, "trollbridge ca uninstall --apply: about to run on %s\n", p.friendly())
	fmt.Fprintf(out, "  source cert (informational): %s\n\n", certPath)
	for i, s := range steps {
		fmt.Fprintf(out, "  step %d: %s\n", i+1, s.desc)
		fmt.Fprintf(out, "          $ %s\n", strings.Join(s.argv, " "))
	}
	fmt.Fprintln(out)

	if !yes {
		fmt.Fprint(out, "Proceed? [y/N]: ")
		if !confirmYes(in) {
			return &runtimeErr{fmt.Errorf("aborted by operator")}
		}
	}

	for i, s := range steps {
		fmt.Fprintf(out, "[%d/%d] %s\n", i+1, len(steps), s.desc)
		if err := runner.run(s, out); err != nil {
			return &runtimeErr{fmt.Errorf("step %d (%s) failed: %w", i+1, s.desc, err)}
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "trollbridge ca uninstall --apply: done.")
	return nil
}
