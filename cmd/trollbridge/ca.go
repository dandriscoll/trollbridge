package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dandriscoll/trollbridge/internal/ca"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/spf13/cobra"
)

// DefaultCACertPath and DefaultCAKeyPath are the canonical locations
// for the trollbridge CA. They are absolute paths so the same value
// is valid on every machine: an operator who scp's a config from one
// host to another finds the cert at the same place. Cwd-relative
// paths (the prior default) are not cross-machine valid and were
// removed in v0.4.7 (issue #14).
const (
	DefaultCACertPath = "/etc/trollbridge/trollbridge-ca.crt"
	DefaultCAKeyPath  = "/etc/trollbridge/trollbridge-ca.key"
	DefaultCADir      = "/etc/trollbridge"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage trollbridge's local CA used for TLS interception.",
	}
	cmd.AddCommand(newCAInitCmd(), newCAExportCmd(), newCAInstallCmd(), newCARotateCmd(), newCAFlushCacheCmd(), newCAClientCertCmd())
	return cmd
}

func newCAClientCertCmd() *cobra.Command {
	var configPath, name, certOut, keyOut string
	cmd := &cobra.Command{
		Use:   "client-cert <name>",
		Short: "Issue a client cert+key for an operator to authenticate with the mTLS control plane.",
		Long: `Issue a client cert (signed by the trollbridge CA) for an operator
to use when calling the mTLS-locked control plane (trollbridge approve,
deny, decisions --pending, sessions, tui, ca flush-cache, rules ...).

Defaults: <name>.crt + <name>.key in the current directory. The
issued cert chains to the same CA used for TLS interception, so the
controller automatically trusts it.

The CLI auto-loads the operator cert from
~/.trollbridge/controller-client.{crt,key} when the
TROLLBRIDGE_CONTROLLER_CERT/_KEY env vars are unset, so naming the
files that way (or symlinking) is the simplest install.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" {
				return &configErr{fmt.Errorf("usage: trollbridge ca client-cert <name>")}
			}
			// Honor cfg.Interception.LeafKeyType from the config so
			// `client-cert` issues leaves with the same key shape the
			// rest of the proxy uses (issue #28). resolveCAArgs reads
			// the field; client-cert previously discarded it.
			cp, kp, ktype, err := resolveCAArgs(configPath, "", "", "")
			if err != nil {
				return &configErr{err}
			}
			caObj, err := ca.Load(cp, kp, ktype, 0)
			if err != nil {
				return &runtimeErr{fmt.Errorf("load CA: %w; fix: trollbridge ca init", err)}
			}
			leaf, err := caObj.IssueClientCert(name)
			if err != nil {
				return &runtimeErr{err}
			}
			certPEM, keyPEM, err := ca.MarshalLeafPEM(leaf)
			if err != nil {
				return &runtimeErr{err}
			}
			if certOut == "" {
				certOut = name + ".crt"
			}
			if keyOut == "" {
				keyOut = name + ".key"
			}
			if err := os.WriteFile(certOut, certPEM, 0o644); err != nil {
				return &runtimeErr{err}
			}
			if err := os.WriteFile(keyOut, keyPEM, 0o600); err != nil {
				return &runtimeErr{err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "trollbridge ca client-cert: issued cert for %q\n", name)
			fmt.Fprintf(out, "  cert: %s\n", certOut)
			fmt.Fprintf(out, "  key:  %s (mode 0600)\n", keyOut)
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "to use as the operator default for this machine, install at:")
			abs := func(p string) string { a, _ := filepath.Abs(p); return a }
			fmt.Fprintf(out, "  ~/.trollbridge/controller-client.crt   ← %s\n", abs(certOut))
			fmt.Fprintf(out, "  ~/.trollbridge/controller-client.key   ← %s\n", abs(keyOut))
			fmt.Fprintln(out, "or set TROLLBRIDGE_CONTROLLER_CERT / _KEY to absolute paths.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path (used to locate the CA)")
	cmd.Flags().StringVar(&name, "name", "", "alternate to positional arg")
	cmd.Flags().StringVar(&certOut, "cert-out", "", "cert output path (default: <name>.crt)")
	cmd.Flags().StringVar(&keyOut, "key-out", "", "key output path (default: <name>.key)")
	return cmd
}

func newCAInitCmd() *cobra.Command {
	var configPath, certPath, keyPath, kt string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a new CA. Refuses if files exist; --force archives them.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cp, kp, ktype, err := resolveCAArgs(configPath, certPath, keyPath, kt)
			if err != nil {
				return &configErr{err}
			}
			c, err := ca.Init(cp, kp, ktype, force)
			if err != nil {
				return &runtimeErr{err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "trollbridge ca init: created files:")
			fmt.Fprintln(out, "  cert:", cp)
			fmt.Fprintln(out, "  key: ", kp, "(mode 0600)")
			fmt.Fprintln(out, "  fingerprint (sha-256):", c.SHA256Fingerprint())
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "next steps:")
			fmt.Fprintln(out, "  trollbridge ca install -c <config>     # show OS-tailored trust-store install commands")
			fmt.Fprintln(out, "  set `interception.enabled: true` in your trollbridge.yaml")
			fmt.Fprintln(out, "  trollbridge run -c <config>")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path (used to locate ca.cert_path / ca.key_path)")
	cmd.Flags().StringVar(&certPath, "cert-out", "", "override cert output path")
	cmd.Flags().StringVar(&keyPath, "key-out", "", "override key output path")
	cmd.Flags().StringVar(&kt, "key-type", "rsa-4096", "rsa-4096 | ecdsa-p256")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.<ts>.bak) and replace")
	return cmd
}

func newCAExportCmd() *cobra.Command {
	var configPath, outPath, certPath string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print the CA cert (public PEM) to stdout or write to --out.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cp, _, _, err := resolveCAArgs(configPath, certPath, "", "")
			if err != nil {
				return &configErr{err}
			}
			data, err := os.ReadFile(cp)
			if err != nil {
				return &runtimeErr{err}
			}
			if outPath == "" {
				_, _ = cmd.OutOrStdout().Write(data)
				return nil
			}
			if err := os.WriteFile(outPath, data, 0o644); err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\nnext: trollbridge ca install   # show OS-tailored trust-store install commands\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	cmd.Flags().StringVar(&certPath, "cert", "", "explicit cert path")
	cmd.Flags().StringVar(&outPath, "out", "", "write to file instead of stdout")
	return cmd
}

func newCARotateCmd() *cobra.Command {
	var configPath, certPath, keyPath, kt string
	var force bool
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new CA, archiving the existing cert+key.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cp, kp, ktype, err := resolveCAArgs(configPath, certPath, keyPath, kt)
			if err != nil {
				return &configErr{err}
			}
			if !force {
				return &configErr{fmt.Errorf("rotate is destructive; pass --force to archive existing files and replace")}
			}
			c, err := ca.Init(cp, kp, ktype, true)
			if err != nil {
				return &runtimeErr{err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "trollbridge ca rotate: prior CA archived; new CA in place.")
			fmt.Fprintln(out, "  fingerprint (sha-256):", c.SHA256Fingerprint())
			fmt.Fprintln(out, "  install the new CA in client trust stores BEFORE existing leaf certs expire")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	cmd.Flags().StringVar(&certPath, "cert-out", "", "override cert output path")
	cmd.Flags().StringVar(&keyPath, "key-out", "", "override key output path")
	cmd.Flags().StringVar(&kt, "key-type", "", "rsa-4096 | ecdsa-p256 (defaults to existing or rsa-4096)")
	cmd.Flags().BoolVar(&force, "force", false, "confirm destructive rotate")
	return cmd
}

func newCAFlushCacheCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "flush-cache",
		Short: "Drop cached leaf certs in a running trollbridge.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			body, err := controlclient.Post(cfg, "/v1/ca/flush-cache", nil)
			if err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	return cmd
}

// resolveCAArgs picks the CA paths from flags or from trollbridge.yaml,
// applying defaults if neither is set.
func resolveCAArgs(configPath, certPath, keyPath, kt string) (string, string, ca.KeyType, error) {
	if certPath == "" || keyPath == "" {
		if configPath == "" {
			configPath = defaultConfigPath()
		}
		cfg, err := config.Load(configPath)
		if err == nil {
			if certPath == "" && cfg.Interception.CA.CertPath != "" {
				certPath = cfg.Interception.CA.CertPath
			}
			if keyPath == "" && cfg.Interception.CA.KeyPath != "" {
				keyPath = cfg.Interception.CA.KeyPath
			}
			if kt == "" && cfg.Interception.LeafKeyType != "" {
				kt = cfg.Interception.LeafKeyType
			}
		}
	}
	if certPath == "" {
		certPath = DefaultCACertPath
	}
	if keyPath == "" {
		keyPath = DefaultCAKeyPath
	}
	if kt == "" {
		kt = "rsa-4096"
	}
	switch kt {
	case "rsa-4096", "ecdsa-p256":
	default:
		return "", "", "", fmt.Errorf("unknown key type %q; use rsa-4096 or ecdsa-p256", kt)
	}
	return certPath, keyPath, ca.KeyType(kt), nil
}
