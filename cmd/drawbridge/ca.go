package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dandriscoll/drawbridge/internal/ca"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage drawbridge's local CA used for TLS interception.",
	}
	cmd.AddCommand(newCAInitCmd(), newCAExportCmd(), newCARotateCmd(), newCAFlushCacheCmd())
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
			fmt.Fprintln(out, "drawbridge ca init: created files:")
			fmt.Fprintln(out, "  cert:", cp)
			fmt.Fprintln(out, "  key: ", kp, "(mode 0600)")
			fmt.Fprintln(out, "  fingerprint (sha-256):", c.SHA256Fingerprint())
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "next steps:")
			fmt.Fprintln(out, "  install the cert into your client trust store; see DESIGN.md §7.5 for OS commands")
			fmt.Fprintln(out, "  set `interception.enabled: true` in your drawbridge.yaml")
			fmt.Fprintln(out, "  drawbridge run -c <config>")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path (used to locate ca.cert_path / ca.key_path)")
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
			return os.WriteFile(outPath, data, 0o644)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
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
			fmt.Fprintln(out, "drawbridge ca rotate: prior CA archived; new CA in place.")
			fmt.Fprintln(out, "  fingerprint (sha-256):", c.SHA256Fingerprint())
			fmt.Fprintln(out, "  install the new CA in client trust stores BEFORE existing leaf certs expire")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
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
		Short: "Drop cached leaf certs in a running drawbridge.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			url := fmt.Sprintf("http://%s/v1/ca/flush-cache", cfg.Approvals.ControlListen)
			httpClient := &http.Client{Timeout: 5 * time.Second}
			resp, err := httpClient.Post(url, "application/json", bytes.NewReader(nil))
			if err != nil {
				return &runtimeErr{fmt.Errorf("control API: %w", err)}
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 400 {
				return &runtimeErr{fmt.Errorf("control API: %s: %s", resp.Status, string(body))}
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
	return cmd
}

// resolveCAArgs picks the CA paths from flags or from drawbridge.yaml,
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
		certPath = "drawbridge-ca.crt"
	}
	if keyPath == "" {
		keyPath = "drawbridge-ca.key"
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
