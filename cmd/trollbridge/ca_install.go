package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/spf13/cobra"
)

// platform is a tagged enum naming the OS / Linux-distro family
// for trust-store install command selection.
type platform string

const (
	platformLinuxDebian  platform = "linux-debian"  // debian, ubuntu, mint, ...
	platformLinuxFedora  platform = "linux-fedora"  // fedora, rhel, centos, rocky, ...
	platformLinuxAlpine  platform = "linux-alpine"
	platformLinuxArch    platform = "linux-arch"
	platformLinuxUnknown platform = "linux-unknown"
	platformDarwin       platform = "darwin"
	platformWindows      platform = "windows"
	platformUnknown      platform = "unknown"
)

func (p platform) friendly() string {
	switch p {
	case platformLinuxDebian:
		return "Linux (Debian / Ubuntu / Mint family)"
	case platformLinuxFedora:
		return "Linux (Fedora / RHEL / CentOS / Rocky family)"
	case platformLinuxAlpine:
		return "Linux (Alpine)"
	case platformLinuxArch:
		return "Linux (Arch / Manjaro)"
	case platformLinuxUnknown:
		return "Linux (unknown distribution)"
	case platformDarwin:
		return "macOS"
	case platformWindows:
		return "Windows"
	default:
		return "unknown OS"
	}
}

// allPlatforms is the order in which --all-platforms emits.
var allPlatforms = []platform{
	platformLinuxDebian, platformLinuxFedora, platformLinuxAlpine, platformLinuxArch,
	platformDarwin, platformWindows,
}

// detectPlatform inspects the live host. Pure logic lives in
// detectPlatformFrom; this thin wrapper supplies the real inputs.
func detectPlatform() platform {
	var osRelease string
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		osRelease = string(b)
	}
	return detectPlatformFrom(runtime.GOOS, osRelease)
}

func detectPlatformFrom(goos, osReleaseContent string) platform {
	switch goos {
	case "darwin":
		return platformDarwin
	case "windows":
		return platformWindows
	case "linux":
		return linuxFamilyFromOSRelease(osReleaseContent)
	default:
		return platformUnknown
	}
}

func linuxFamilyFromOSRelease(content string) platform {
	if content == "" {
		return platformLinuxUnknown
	}
	id, idLike := "", ""
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "ID_LIKE="):
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	hay := strings.ToLower(id + " " + idLike)
	switch {
	case containsAny(hay, "debian", "ubuntu", "mint", "pop"):
		return platformLinuxDebian
	case containsAny(hay, "fedora", "rhel", "centos", "rocky", "almalinux"):
		return platformLinuxFedora
	case containsAny(hay, "alpine"):
		return platformLinuxAlpine
	case containsAny(hay, "arch", "manjaro"):
		return platformLinuxArch
	default:
		return platformLinuxUnknown
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// installCommandsFor returns the copy-pasteable install commands
// for one platform, given the resolved cert path. Pure: no I/O.
func installCommandsFor(p platform, certPath string) []string {
	switch p {
	case platformLinuxDebian, platformLinuxAlpine:
		return []string{
			"sudo cp " + certPath + " /usr/local/share/ca-certificates/trollbridge-ca.crt",
			"sudo update-ca-certificates",
		}
	case platformLinuxFedora:
		return []string{
			"sudo cp " + certPath + " /etc/pki/ca-trust/source/anchors/trollbridge-ca.crt",
			"sudo update-ca-trust",
		}
	case platformLinuxArch:
		return []string{
			"sudo trust anchor --store " + certPath,
			"# (alternative) sudo cp " + certPath + " /etc/ca-certificates/trust-source/anchors/ && sudo trust extract-compat",
		}
	case platformLinuxUnknown:
		return []string{
			"# Linux distribution not auto-detected.",
			"# Try: sudo cp " + certPath + " /usr/local/share/ca-certificates/trollbridge-ca.crt && sudo update-ca-certificates",
			"# Or:  sudo cp " + certPath + " /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust",
			"# See `trollbridge ca install --all-platforms` for every variant.",
		}
	case platformDarwin:
		return []string{
			"# user keychain (no sudo, applies to current user only):",
			"security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db " + certPath,
			"",
			"# system keychain (sudo, applies to every user on this Mac):",
			"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + certPath,
		}
	case platformWindows:
		return []string{
			"# run from an elevated (Administrator) PowerShell or cmd.exe:",
			`certutil -addstore -f "Root" ` + certPath,
			"",
			"# (alternative) Import-Certificate -FilePath " + certPath + ` -CertStoreLocation Cert:\LocalMachine\Root`,
		}
	default:
		return []string{
			"# OS not detected — see `trollbridge ca install --all-platforms`.",
		}
	}
}

// runtimeOptionsBlock prints language-runtime trust-bundle options
// that work without modifying the system trust store. Useful when
// (a) the operator can't sudo, (b) only one process needs to trust
// the CA, or (c) the language runtime ignores the system store.
func runtimeOptionsBlock(certPath string) []string {
	return []string{
		"# Per-runtime, no sudo required. Set in the env where the client runs:",
		"export NODE_EXTRA_CA_CERTS=" + certPath + "      # Node.js",
		"export SSL_CERT_FILE=" + certPath + "             # Python (httpx, ssl), Go (Linux)",
		"export REQUESTS_CA_BUNDLE=" + certPath + "        # Python `requests`",
		"export CURL_CA_BUNDLE=" + certPath + "            # curl",
		"# Java (no env var; one-shot import into the truststore):",
		"#   sudo keytool -importcert -trustcacerts -alias trollbridge -file " + certPath + ` -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit`,
	}
}

// certFingerprint returns the SHA-256 hex fingerprint of a
// PEM-encoded x509 cert at the given path. Used by `ca install`
// to display the same fingerprint `ca init` printed at creation.
func certFingerprint(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func newCAInstallCmd() *cobra.Command {
	var configPath, certPath string
	var allPlatformsFlag, applyFlag, yesFlag bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Print (or, with --apply, run) the commands to install the trollbridge CA.",
		Long: `Print the OS-tailored commands needed to install the trollbridge
CA into a system trust store (or a per-runtime trust bundle).

By default this subcommand does NOT execute system commands; it
prints them so an operator can review and copy. Re-run with
--all-platforms to dump every supported platform.

With --apply, trollbridge will run the system-trust-store install
commands itself. --apply requires elevated privileges (root on
Linux/macOS); if not elevated, --apply refuses with a clear
message instead of invoking sudo. --apply is not supported on
Windows or unrecognized Linux distributions — copy the printed
commands instead. The runtime-specific options (NODE_EXTRA_CA_CERTS
etc.) stay print-only regardless of --apply.

By default --apply prompts for confirmation; pass --yes to skip.

Cert resolution (in priority order):
  1. --cert <path>           explicit, overrides everything
  2. --config <yaml>         the file's interception.ca.cert_path,
                             if the file exists
  3. canonical system paths  /etc/trollbridge/trollbridge-ca.crt,
                             then /usr/local/share/ca-certificates/
                             trollbridge-ca.crt — first that exists
                             wins. Cwd is intentionally NOT searched:
                             cert paths must be cross-machine stable.

Whatever path is selected, the printed install commands use its
absolute form so they remain valid when pasted into another shell
or another machine.

In a remote-mode topology (the trollbridge daemon runs on a
different host than the consumer apps), copy the cert from the
daemon host to /etc/trollbridge/trollbridge-ca.crt on the consumer;
this command will find it without --cert.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgCert, _ := configCertPath(configPath)
			cp, err := findInstallCert(certPath, cfgCert, os.Stat)
			if err != nil {
				return &configErr{err}
			}
			// Resolve to absolute so the printed install commands
			// work when pasted from any cwd or any machine. Defends
			// against operators passing --cert ./relative/path —
			// without this, the printed `cp ./relative/path …`
			// would break on paste.
			if abs, aerr := filepath.Abs(cp); aerr == nil {
				cp = abs
			}
			if applyFlag {
				return applyInstall(
					cmd.OutOrStdout(),
					cmd.InOrStdin(),
					detectPlatform(),
					cp,
					yesFlag,
					execStepRunner{},
					func() bool { return os.Geteuid() == 0 },
				)
			}
			printInstallHelp(cmd.OutOrStdout(), cp, allPlatformsFlag, detectPlatform())
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	cmd.Flags().StringVar(&certPath, "cert", "", "explicit cert path (overrides config and canonical-path search)")
	cmd.Flags().BoolVar(&allPlatformsFlag, "all-platforms", false, "print install commands for every supported platform")
	cmd.Flags().BoolVar(&applyFlag, "apply", false, "execute the system trust-store install (requires root)")
	cmd.Flags().BoolVar(&yesFlag, "yes", false, "with --apply: skip the confirmation prompt")
	return cmd
}

// installCertCandidates returns the canonical paths `ca install`
// searches, in priority order, when neither --cert nor a config-
// derived path is supplied. Cwd-relative paths are deliberately NOT
// in this list — the cert location must be cross-machine stable, and
// `./trollbridge-ca.crt` is not (issue #14). An operator who wants a
// non-canonical path passes --cert <abs>.
func installCertCandidates() []string {
	return []string{
		DefaultCACertPath,
		"/usr/local/share/ca-certificates/trollbridge-ca.crt",
	}
}

// findInstallCert resolves the cert path for `ca install`.
//   1. If `explicit` is non-empty, return it as-is. The applyInstall
//      path will surface a detailed error if it does not exist.
//   2. If `configCert` is non-empty and the file exists, return it.
//   3. Walk installCertCandidates() and return the first existing.
//   4. Otherwise return an error that names every searched path so
//      the operator can place the cert at the canonical Debian
//      drop-in location, or pass --cert.
//
// `statFn` is injected so tests can drive the search without
// touching the live filesystem.
func findInstallCert(explicit, configCert string, statFn func(string) (os.FileInfo, error)) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if configCert != "" {
		if _, err := statFn(configCert); err == nil {
			return configCert, nil
		}
	}
	candidates := installCertCandidates()
	for _, p := range candidates {
		if _, err := statFn(p); err == nil {
			return p, nil
		}
	}
	searched := candidates
	if configCert != "" {
		searched = append([]string{configCert + " (from --config)"}, candidates...)
	}
	return "", fmt.Errorf(
		"trollbridge CA cert not found. Searched:\n  - %s\nFix: place the cert at %s (the canonical location), or pass --cert <absolute path>. In a remote-mode topology, scp the cert from the trollbridge host to %s on the consumer host.",
		strings.Join(searched, "\n  - "),
		DefaultCACertPath, DefaultCACertPath,
	)
}

// configCertPath loads trollbridge.yaml at configPath (or the
// default) and returns the configured interception.ca.cert_path.
// Errors are swallowed — `ca install` does not require a yaml to
// exist (the canonical-path search covers the case where the
// consumer host has no trollbridge.yaml).
func configCertPath(configPath string) (string, error) {
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", nil //nolint:nilerr // intentional: missing yaml is fine for ca install
	}
	return cfg.Interception.CA.CertPath, nil
}

func printInstallHelp(out io.Writer, certPath string, allPlatformsFlag bool, detected platform) {
	fmt.Fprintf(out, "trollbridge CA: %s\n", certPath)
	if _, err := os.Stat(certPath); err != nil {
		fmt.Fprintf(out, "  (note: %s does not exist; run `trollbridge ca init` first to create it)\n", certPath)
	} else if fp, err := certFingerprint(certPath); err == nil {
		fmt.Fprintf(out, "fingerprint (sha-256): %s\n", fp)
	}
	fmt.Fprintln(out)

	platforms := []platform{detected}
	if allPlatformsFlag {
		platforms = allPlatforms
	}
	for _, p := range platforms {
		fmt.Fprintf(out, "== System trust store: %s ==\n", p.friendly())
		for _, line := range installCommandsFor(p, certPath) {
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintln(out, "== Runtime-specific options (alternative to system trust store) ==")
	for _, line := range runtimeOptionsBlock(certPath) {
		fmt.Fprintln(out, line)
	}
	if !allPlatformsFlag {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "For other platforms: trollbridge ca install --all-platforms")
	}
}
