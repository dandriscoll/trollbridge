package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/ca"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/spf13/cobra"
)

// newDiagnoseCmd is the parent of trollbridge's per-feature diagnostic
// subcommands. Today only `diagnose tls` exists; future additions
// (e.g., `diagnose advisor`, `diagnose audit`) would slot in here so
// the operator-facing surface stays grouped.
func newDiagnoseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Probe trollbridge subsystems for misconfiguration.",
		Long: `Diagnose runs read-only probes against trollbridge's working
configuration. Unlike 'doctor' (which verifies the config can load
and the LLM is reachable), 'diagnose' inspects a specific
subsystem's runtime behavior end-to-end.

Currently supported:
  diagnose tls <host>          inspect the cert the proxy would
                                serve for <host>, or probe the
                                client-facing handshake when --probe
                                is set.`,
	}
	cmd.AddCommand(newDiagnoseTLSCmd())
	return cmd
}

// newDiagnoseTLSCmd implements `trollbridge diagnose tls <host>`.
//
// Two modes, sharing one subcommand because operators reach for both
// when chasing the same symptom:
//
//   Inside-out (default): load the proxy CA and mint the same leaf
//     cert interceptCONNECT would mint for <host>. Print cert
//     subject, SANs, issuer, validity, fingerprint, ALPN, min TLS
//     version. Purely local; doesn't dial anywhere.
//
//   Outside-in (--probe): dial the configured proxy as a synthetic
//     client. Send CONNECT <host>:<port>, perform a TLS handshake
//     (verifying against the proxy CA if --trust-proxy-ca is set;
//     otherwise InsecureSkipVerify and report what the peer sent).
//     Report negotiated version, ALPN, peer cert chain, and any
//     classified error category on handshake failure.
func newDiagnoseTLSCmd() *cobra.Command {
	var (
		configPath    string
		port          int
		probe         bool
		trustProxyCA  bool
		alpn          []string
		minVersion    string
		insecure      bool
		timeoutSec    int
	)
	cmd := &cobra.Command{
		Use:   "tls <host>",
		Short: "Inspect / probe TLS interception for a target host.",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			host := args[0]
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{fmt.Errorf("load config %s: %w", configPath, err)}
			}
			out := c.OutOrStdout()
			if probe {
				return diagnoseTLSProbe(out, cfg, host, port, alpn, minVersion, trustProxyCA, insecure, timeoutSec)
			}
			return diagnoseTLSServeCert(out, cfg, host)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().IntVar(&port, "port", 443, "destination port for --probe (CONNECT host:port)")
	cmd.Flags().BoolVar(&probe, "probe", false, "outside-in: dial the configured proxy and perform a TLS handshake")
	cmd.Flags().BoolVar(&trustProxyCA, "trust-proxy-ca", true, "probe: verify the proxy's cert against the configured CA (default true)")
	cmd.Flags().StringSliceVar(&alpn, "alpn", []string{"http/1.1"}, "probe: ALPN protocols to offer")
	cmd.Flags().StringVar(&minVersion, "min-tls", "1.2", "probe: minimum TLS version (1.0|1.1|1.2|1.3)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "probe: skip cert verification (overrides --trust-proxy-ca)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "probe: handshake timeout in seconds")
	return cmd
}

// diagnoseTLSServeCert is the inside-out mode: load the proxy CA and
// print what cert it would serve for `host`. No network I/O.
func diagnoseTLSServeCert(out io.Writer, cfg *config.Config, host string) error {
	if !cfg.Interception.Enabled {
		fmt.Fprintln(out, "interception: DISABLED in config (interception.enabled: false)")
		fmt.Fprintln(out, "the proxy would NOT serve a cert for this host — CONNECT tunnels are blind-piped.")
		return nil
	}
	caCertPath := cfg.Interception.CA.CertPath
	caKeyPath := cfg.Interception.CA.KeyPath
	if caCertPath == "" || caKeyPath == "" {
		return &configErr{fmt.Errorf("interception.ca.cert_path and key_path must be set in %s", "trollbridge.yaml")}
	}
	leafKT := ca.KeyType(cfg.Interception.LeafKeyType)
	leafTTL := time.Duration(cfg.Interception.LeafCertTTLHours) * time.Hour
	if leafTTL == 0 {
		leafTTL = 365 * 24 * time.Hour
	}
	caInst, err := ca.Load(caCertPath, caKeyPath, leafKT, leafTTL)
	if err != nil {
		return &configErr{fmt.Errorf("load CA: %w", err)}
	}
	fmt.Fprintf(out, "trollbridge diagnose tls %s (inside-out)\n", host)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "CA")
	fmt.Fprintf(out, "  cert_path:   %s\n", caCertPath)
	fmt.Fprintf(out, "  subject:     %s\n", caInst.Cert.Subject.String())
	fmt.Fprintf(out, "  fingerprint: %s\n", colonSHA256(caInst.SHA256Fingerprint()))
	fmt.Fprintf(out, "  not_after:   %s\n", caInst.Cert.NotAfter.UTC().Format(time.RFC3339))
	leaf, err := caInst.LeafFor(host)
	if err != nil {
		return &runtimeErr{fmt.Errorf("mint leaf cert: %w", err)}
	}
	if leaf.Leaf == nil {
		// Defensive: LeafFor always populates Leaf, but if a future
		// refactor stops doing that, fail loud rather than panic.
		return &runtimeErr{fmt.Errorf("leaf cert missing parsed form")}
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Leaf the proxy would serve")
	fmt.Fprintf(out, "  subject:     %s\n", leaf.Leaf.Subject.String())
	fmt.Fprintf(out, "  issuer:      %s\n", leaf.Leaf.Issuer.String())
	fmt.Fprintf(out, "  dns_names:   %v\n", leaf.Leaf.DNSNames)
	if len(leaf.Leaf.IPAddresses) > 0 {
		fmt.Fprintf(out, "  ip_addrs:    %v\n", leaf.Leaf.IPAddresses)
	}
	fmt.Fprintf(out, "  not_before:  %s\n", leaf.Leaf.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  not_after:   %s\n", leaf.Leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  fingerprint: %s\n", colonSHA256(leafFingerprint(leaf.Leaf)))
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Server config the proxy would advertise")
	fmt.Fprintln(out, "  alpn:        http/1.1")
	fmt.Fprintln(out, "  min_tls:     1.2")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "To run the outside-in probe (actually dial the proxy):")
	fmt.Fprintf(out, "  trollbridge diagnose tls %s --probe\n", host)
	return nil
}

// diagnoseTLSProbe is the outside-in mode: dial the proxy as a
// synthetic client, send CONNECT, perform a TLS handshake. Prints
// what the proxy actually served (or how the handshake failed).
func diagnoseTLSProbe(
	out io.Writer,
	cfg *config.Config,
	host string,
	port int,
	alpn []string,
	minVersion string,
	trustProxyCA bool,
	insecure bool,
	timeoutSec int,
) error {
	proxyAddr := cfg.Proxy.Addr()
	if proxyAddr == "" {
		return &configErr{fmt.Errorf("config has no proxy bind; cannot probe without a listening proxy")}
	}
	fmt.Fprintf(out, "trollbridge diagnose tls %s --probe (outside-in)\n", host)
	fmt.Fprintf(out, "  proxy_addr:  %s\n", proxyAddr)
	fmt.Fprintf(out, "  target:      %s:%d\n", host, port)
	fmt.Fprintf(out, "  alpn:        %s\n", strings.Join(alpn, ","))
	fmt.Fprintf(out, "  min_tls:     %s\n", minVersion)
	fmt.Fprintln(out, "")

	minV, err := parseTLSVersion(minVersion)
	if err != nil {
		return &configErr{err}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	d := &net.Dialer{}
	rawConn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		fmt.Fprintf(out, "tcp_connect: FAIL (%s)\n", err.Error())
		return &runtimeErr{err}
	}
	defer rawConn.Close()
	fmt.Fprintln(out, "tcp_connect: OK")

	// CONNECT host:port HTTP/1.1
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	if _, err := rawConn.Write([]byte(connectReq)); err != nil {
		fmt.Fprintf(out, "connect_write: FAIL (%s)\n", err.Error())
		return &runtimeErr{err}
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		fmt.Fprintf(out, "connect_response: FAIL (%s)\n", err.Error())
		return &runtimeErr{err}
	}
	resp.Body.Close()
	fmt.Fprintf(out, "connect_response: %d %s\n", resp.StatusCode, resp.Status)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(out, "  proxy rejected CONNECT; not attempting TLS handshake\n")
		return &runtimeErr{fmt.Errorf("proxy CONNECT returned %d", resp.StatusCode)}
	}

	// Build TLS config for the client side.
	tlsCfg := &tls.Config{
		ServerName: host,
		NextProtos: append([]string(nil), alpn...),
		MinVersion: minV,
	}
	switch {
	case insecure:
		tlsCfg.InsecureSkipVerify = true
		fmt.Fprintln(out, "  trust: insecure (cert verification skipped)")
	case trustProxyCA && cfg.Interception.Enabled && cfg.Interception.CA.CertPath != "":
		pool, err := loadCAPool(cfg.Interception.CA.CertPath)
		if err != nil {
			return &configErr{fmt.Errorf("load proxy CA for trust pool: %w", err)}
		}
		tlsCfg.RootCAs = pool
		fmt.Fprintf(out, "  trust: proxy CA at %s\n", cfg.Interception.CA.CertPath)
	default:
		fmt.Fprintln(out, "  trust: system roots")
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	_ = rawConn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	handshakeStart := time.Now()
	hsErr := tlsConn.HandshakeContext(ctx)
	handshakeMS := time.Since(handshakeStart).Milliseconds()
	if hsErr != nil {
		category := classifyProbeError(hsErr)
		fmt.Fprintf(out, "tls_handshake: FAIL (%d ms)\n", handshakeMS)
		fmt.Fprintf(out, "  error:       %s\n", hsErr.Error())
		fmt.Fprintf(out, "  category:    %s\n", category)
		hintForProbeFailure(out, category)
		return &runtimeErr{hsErr}
	}
	state := tlsConn.ConnectionState()
	fmt.Fprintf(out, "tls_handshake: OK (%d ms)\n", handshakeMS)
	fmt.Fprintf(out, "  version:     %s\n", tlsVersionLabel(state.Version))
	fmt.Fprintf(out, "  cipher:      %s\n", tls.CipherSuiteName(state.CipherSuite))
	if state.NegotiatedProtocol != "" {
		fmt.Fprintf(out, "  alpn:        %s\n", state.NegotiatedProtocol)
	} else {
		fmt.Fprintln(out, "  alpn:        (none negotiated)")
	}
	for i, cert := range state.PeerCertificates {
		fmt.Fprintf(out, "  peer_cert[%d].subject: %s\n", i, cert.Subject.String())
		fmt.Fprintf(out, "  peer_cert[%d].issuer:  %s\n", i, cert.Issuer.String())
		if i == 0 {
			fmt.Fprintf(out, "  peer_cert[0].dns:     %v\n", cert.DNSNames)
			fmt.Fprintf(out, "  peer_cert[0].not_after: %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	_ = tlsConn.Close()
	return nil
}

// classifyProbeError reuses the server-side classifier so the
// operator-facing taxonomy is the same on both sides. The probe is
// the *client* in the handshake, so the origin-side shape (cert
// validation against the proxy CA) is the better starting point;
// fall back to the client-handshake shape if origin returns unknown.
func classifyProbeError(err error) server.TLSErrorCategory {
	if c := server.ClassifyOriginTLSError(err); c != "" && c != server.TLSErrUnknown {
		return c
	}
	return server.ClassifyClientHandshakeError(err)
}

func hintForProbeFailure(out io.Writer, c server.TLSErrorCategory) {
	switch c {
	case server.TLSErrClientRejectedCA:
		fmt.Fprintln(out, "  hint:        the probe did not trust the proxy CA. Re-run with --trust-proxy-ca")
		fmt.Fprintln(out, "               (default true) or --insecure. If a real agent is failing the same")
		fmt.Fprintln(out, "               way, install the proxy CA into its trust store.")
	case server.TLSErrClientALPNMismatch:
		fmt.Fprintln(out, "  hint:        the proxy advertises http/1.1 only. Offer http/1.1 in the client's ALPN list.")
	case server.TLSErrClientVersionUnsupported:
		fmt.Fprintln(out, "  hint:        the proxy requires TLS 1.2+. Raise the client's min TLS version.")
	case server.TLSErrHandshakeTimeout:
		fmt.Fprintln(out, "  hint:        the proxy did not complete the handshake within --timeout. Check that")
		fmt.Fprintln(out, "               interception is enabled for the target host (not in passthrough_hosts).")
	}
}

// colonSHA256 turns "abcd..." into "AB:CD:..." for the standard
// human-readable fingerprint shape.
func colonSHA256(hex string) string {
	if len(hex)%2 != 0 {
		return hex
	}
	parts := make([]string, 0, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, strings.ToUpper(hex[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func leafFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func parseTLSVersion(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unknown TLS version %q (want 1.0|1.1|1.2|1.3)", v)
}

func tlsVersionLabel(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func loadCAPool(certPath string) (*x509.CertPool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				pool.AddCert(cert)
			}
		}
		data = rest
	}
	return pool, nil
}

