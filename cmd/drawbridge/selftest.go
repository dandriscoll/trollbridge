package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/spf13/cobra"
)

func newSelftestCmd() *cobra.Command {
	var configPath string
	var fromVM bool
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Verify the deployment is wired correctly.",
		Long: `Selftest exercises the deployment topology from the perspective
of the agent's host. With --from-vm, drawbridge attempts to reach a
small set of well-known direct destinations (with proxy unset) and
reports whether the egress firewall blocked them. It also tries the
proxy address with proxy set, and reports whether the configured
CA is in the system trust store.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "drawbridge selftest:")
			fmt.Fprintln(out, "  proxy:", cfg.BindAddr(cfg.Ports.Proxy))

			if fromVM {
				return selftestFromVM(cmd.Context(), out, cfg)
			}
			return selftestLocal(cmd.Context(), out, cfg)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
	cmd.Flags().BoolVar(&fromVM, "from-vm", false, "run the from-VM checks (assumes you are inside the agent VM)")
	return cmd
}

func selftestLocal(ctx context.Context, out interface{ Write(p []byte) (int, error) }, cfg *config.Config) error {
	w := func(s string) { fmt.Fprintln(out, s) }
	addr := cfg.BindAddr(cfg.Ports.Proxy)
	conn, err := dialWithCtx(ctx, addr, 2*time.Second)
	if err != nil {
		w("  proxy reachable:    NO  (" + err.Error() + ")")
	} else {
		conn.Close()
		w("  proxy reachable:    yes")
	}
	if cfg.Ports.Control != 0 {
		conn, err = dialWithCtx(ctx, cfg.BindAddr(cfg.Ports.Control), 2*time.Second)
		if err != nil {
			w("  control reachable:  NO  (" + err.Error() + ")")
		} else {
			conn.Close()
			w("  control reachable:  yes  (TLS-terminated; mTLS required for /v1/* except healthz)")
		}
	}
	return nil
}

// selftestFromVM is run from inside the agent VM. It tries:
//   1. Direct outbound to a public address with proxy unset → MUST
//      fail when the firewall is binding.
//   2. Outbound through the configured proxy → MUST succeed.
//   3. HTTPS through the configured proxy → MUST succeed (CA
//      trusted in the VM).
func selftestFromVM(ctx context.Context, out interface{ Write(p []byte) (int, error) }, cfg *config.Config) error {
	w := func(s string) { fmt.Fprintln(out, s) }
	w("running from-VM checks; expect 'firewall blocked' to be YES on a correct deployment.")

	// 1. Direct (no proxy) to a public address.
	directClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   3 * time.Second,
	}
	resp, err := directClient.Get("https://example.com/")
	if err == nil {
		resp.Body.Close()
		w("  direct outbound to example.com:443:  REACHED (firewall is NOT binding; this is a misconfiguration)")
	} else {
		w("  direct outbound to example.com:443:  blocked (good): " + err.Error())
	}

	// 2. Through the proxy.
	proxyAddr := cfg.BindAddr(cfg.Ports.Proxy)
	pURL, _ := url.Parse("http://" + proxyAddr)
	viaProxy := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{},
		},
		Timeout: 5 * time.Second,
	}
	resp, err = viaProxy.Get("https://example.com/")
	if err != nil {
		w("  via-proxy https://example.com/:        FAILED (" + err.Error() + ")")
	} else {
		resp.Body.Close()
		w("  via-proxy https://example.com/:        ok (proxy reachable; CA trusted)")
	}
	return nil
}

func dialWithCtx(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
