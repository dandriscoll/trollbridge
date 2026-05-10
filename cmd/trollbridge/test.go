package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/spf13/cobra"
)

const (
	testDefaultBodyShow         = 4096
	testBodyReadCap             = 1 << 20 // 1 MiB
	testRawBodyCap              = 1 << 30 // 1 GiB ceiling even with --raw
	testDefaultTimeoutSec       = 30
	testCorrelationDeadlineMS   = 250
	testCorrelationPollMS       = 25
	testCorrelationScanWindowB  = 64 << 10
)

func newTestCmd() *cobra.Command {
	var (
		configPath string
		method     string
		headers    []string
		body       string
		bodyFile   string
		showBody   int
		raw        bool
		timeoutSec int
		noDecision bool
		printCurl  bool
		caFile     string
		verbose    bool
	)
	cmd := &cobra.Command{
		Use:   "test <url>",
		Short: "Send a single request through the running proxy and print the proxy's decision plus the response.",
		Long: `Test sends one HTTP/HTTPS request through the running trollbridge
proxy (proxy address is read from trollbridge.yaml) and prints both
the proxy's decision (allow / deny / hold + matching rule, resolved
from the audit log) and the upstream response (status, selected
headers, body).

Examples:

  trollbridge test https://api.github.com/zen
  trollbridge test -X POST -H 'Content-Type: application/json' \
                  --body '{"q":"hi"}' https://api.openai.com/v1/chat/completions

For HTTPS URLs with TLS interception enabled, the test client
automatically trusts the configured trollbridge CA. With interception
disabled, the proxy is a transparent CONNECT tunnel and the test
client must already trust the upstream's certificate.

Held requests (under default-ask) return HTTP 471 (Trollbridge
pending approval); declined requests return HTTP 470 (Trollbridge
declined). Both statuses are intentionally non-standard so the
caller can distinguish a proxy decision from any upstream code.
This command surfaces the hold and the operator command needed
to approve it.

Decision correlation reads the audit log named by trollbridge.yaml's
logging.audit_path. Under heavy concurrent traffic the matched
entry is "newest matching (method, host, path)"; for an idle proxy
this is unambiguous.

Use --print-curl to emit an equivalent curl command (two variants:
proxy env embedded inline, and bare) instead of sending the request.
The flag does not contact the proxy daemon; --show-body, --raw,
--timeout, and --no-decision do not apply under --print-curl.
The emitted curl command targets the proxy at the address from
trollbridge.yaml; the host that runs the curl command must share
network reachability with the daemon.`,
		Args: requireURLArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}
			req, err := buildTestRequest(args[0], method, headers, body, bodyFile)
			if err != nil {
				return &configErr{err}
			}
			if printCurl {
				// Defense-in-depth: config.Load rejects `proxy: 0` today,
				// but if that contract relaxes, an empty proxy address
				// would silently emit `https_proxy='http://' curl …`.
				// Match runTest's disabled() guard for symmetry.
				if cfg.Proxy.Disabled() {
					return &configErr{fmt.Errorf("proxy is disabled in trollbridge.yaml (proxy: 0); set proxy: lo:8080 (or another bind) so --print-curl knows what proxy address to embed")}
				}
				renderCurl(cmd.OutOrStdout(), req, body, bodyFile, cfg.Proxy.ClientAddr())
				return nil
			}
			to := time.Duration(timeoutSec) * time.Second
			if timeoutSec <= 0 {
				to = 0
			}
			return runTest(cmd.Context(), cmd.OutOrStdout(), cfg, req, testOpts{
				ShowBody:   showBody,
				Raw:        raw,
				Timeout:    to,
				NoDecision: noDecision,
				ConfigPath: configPath,
				CAFile:     caFile,
				Verbose:    verbose,
			})
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "trollbridge.yaml path")
	cmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "extra request header (\"KEY: VALUE\"; repeatable)")
	cmd.Flags().StringVar(&body, "body", "", "request body (string)")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "request body (file path; mutually exclusive with --body)")
	cmd.Flags().IntVar(&showBody, "show-body", testDefaultBodyShow, "max bytes of response body to print (0 = none)")
	cmd.Flags().BoolVar(&raw, "raw", false, "print full response body, no truncation (suppresses --show-body)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", testDefaultTimeoutSec, "per-request timeout in seconds (0 = no timeout)")
	cmd.Flags().BoolVar(&noDecision, "no-decision", false, "skip audit-log decision correlation")
	cmd.Flags().BoolVar(&printCurl, "print-curl", false, "print an equivalent curl command (proxy env embedded, and bare) instead of sending the request")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "trust this CA file for HTTPS (overrides interception.ca.cert_path; useful when interception is off and the upstream uses a private CA)")
	cmd.Flags().StringVar(&caFile, "cacert", "", "alias for --ca-file (curl convention)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print connection-level events (DNS, connect, TLS handshake, first byte) before the response")
	return cmd
}

type testOpts struct {
	ShowBody   int
	Raw        bool
	Timeout    time.Duration
	NoDecision bool
	ConfigPath string
	// CAFile, when non-empty, overrides cfg.Interception.CA.CertPath
	// for the test client's TLS trust pool. Loaded regardless of
	// cfg.Interception.Enabled — testers who use private upstreams
	// without interception still need a way to trust them.
	CAFile string
	// Verbose attaches an httptrace.ClientTrace to the request so
	// connection-level events (DNS, connect, TLS handshake, first
	// byte) print to out before the response section.
	Verbose bool
	// MaxBodyLines, when > 0, caps the rendered body at the first N
	// newline-bounded lines after the ShowBody byte cap is applied.
	// The REPL's small console pane sets this so a chatty endpoint's
	// body cannot push the status / decision / reason lines off
	// screen (closes #40); the CLI leaves it 0 (byte-cap only).
	MaxBodyLines int
	// MaxHeaders, when > 0, caps the response-header block to a
	// curated subset (Content-Type, Content-Length) plus the first
	// (MaxHeaders - len(curated)) headers in alphabetical order; the
	// remainder is summarized as "(N more headers omitted)". The REPL's
	// small console pane sets this for the same reason MaxBodyLines
	// exists — chatty endpoints emit 10+ headers (Set-Cookie,
	// Cache-Control, X-Frame-Options, …) that scroll status / decision
	// / reason lines off the small pane (closes #40). The CLI leaves
	// it 0 (no cap). MaxHeaders is independent of the Raw flag: --raw
	// governs the response body only.
	MaxHeaders int
}

// requireURLArg replaces cobra.ExactArgs(1) so the user sees a usage
// block and concrete examples — not just "accepts 1 arg(s), received N"
// — when they run `trollbridge test` without (or with the wrong number
// of) positional arguments. Returned error is wrapped to configErr by
// the caller's RunE; here we just shape the message.
func requireURLArg(cmd *cobra.Command, args []string) error {
	if len(args) == 1 {
		return nil
	}
	var lead string
	if len(args) == 0 {
		lead = "trollbridge test takes one URL argument; got none."
	} else {
		lead = fmt.Sprintf("trollbridge test takes exactly one URL argument; got %d.", len(args))
	}
	return fmt.Errorf(`%s

Usage:
  trollbridge test [flags] <url>

Common flags:
  -X, --method        HTTP method (default GET)
  -H, --header        extra request header (repeatable, "KEY: VALUE")
      --body          request body (string)
      --body-file     request body (file path; mutually exclusive with --body)
      --show-body N   max bytes of response body to print (default 4096)
      --raw           print full response body (no truncation)
      --timeout N     per-request timeout in seconds (0 = none)
      --no-decision   skip audit-log decision correlation
      --print-curl    emit equivalent curl commands instead of sending
  -c, --config        trollbridge.yaml path (default ./trollbridge.yaml)

Examples:
  trollbridge test https://api.github.com/zen
  trollbridge test -X POST -H 'Content-Type: application/json' \
                  --body '{"q":"hi"}' https://api.openai.com/v1/chat/completions
  trollbridge test --print-curl https://api.github.com/zen

Run 'trollbridge test --help' for the full reference.`, lead)
}

func buildTestRequest(rawURL, method string, headers []string, body, bodyFile string) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL must include scheme http:// or https://; got %q", rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL is missing host: %q", rawURL)
	}
	u.User = nil
	if body != "" && bodyFile != "" {
		return nil, fmt.Errorf("--body and --body-file are mutually exclusive")
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else if bodyFile != "" {
		b, err := os.ReadFile(bodyFile)
		if err != nil {
			return nil, fmt.Errorf("read --body-file: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = http.MethodGet
	}
	req, err := http.NewRequest(m, u.String(), rdr)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return nil, fmt.Errorf("--header must be \"KEY: VALUE\"; got %q", h)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return nil, fmt.Errorf("--header has empty key: %q", h)
		}
		req.Header.Add(k, v)
	}
	return req, nil
}

func runTest(ctx context.Context, out io.Writer, cfg *config.Config, req *http.Request, opts testOpts) error {
	if cfg.Proxy.Disabled() {
		return &configErr{fmt.Errorf("proxy is disabled in trollbridge.yaml (proxy: 0); set proxy: lo:8080 (or another bind) and run trollbridge run")}
	}
	proxyAddr := cfg.Proxy.ClientAddr()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return &configErr{fmt.Errorf("parse proxy addr %q: %w", proxyAddr, err)}
	}

	tlsCfg := &tls.Config{}
	caSource := ""
	switch {
	case opts.CAFile != "":
		// Operator override (--ca-file). Load regardless of whether
		// interception is enabled in the config — the operator may
		// be testing a private CA-signed upstream directly.
		pool, perr := loadInterceptionCA(opts.CAFile)
		if perr != nil {
			return &configErr{fmt.Errorf("--ca-file %s: %w", opts.CAFile, perr)}
		}
		tlsCfg.RootCAs = pool
		caSource = opts.CAFile
	case cfg.Interception.Enabled && cfg.Interception.CA.CertPath != "":
		pool, perr := loadInterceptionCA(cfg.Interception.CA.CertPath)
		if perr == nil {
			tlsCfg.RootCAs = pool
			caSource = cfg.Interception.CA.CertPath
		} else {
			fmt.Fprintf(os.Stderr, "trollbridge test: warning: configured interception CA at %s is unreadable (%v); falling back to system trust\n",
				cfg.Interception.CA.CertPath, perr)
		}
	}

	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}
	if opts.Timeout > 0 {
		client.Timeout = opts.Timeout
	}

	printTestPreamble(out, req, proxyAddr, opts.ConfigPath, string(cfg.Mode), cfg.Interception.Enabled)
	if caSource != "" {
		// Surface which CA is in play so an operator who mismatches
		// --ca-file with the upstream's signing CA sees the source
		// in the transcript without having to re-run with -v. When
		// --ca-file is set but interception is off, tag the line so
		// the operator knows it applies to direct (non-intercepted)
		// HTTPS to a host whose chain this CA validates.
		tag := "ca-file:    "
		if opts.CAFile != "" && !cfg.Interception.Enabled {
			tag = "ca-file:    "
			fmt.Fprintf(out, "%s%s (note: interception is off; --ca-file applies to direct HTTPS only)\n", tag, caSource)
		} else {
			fmt.Fprintf(out, "%s%s\n", tag, caSource)
		}
	}

	startedAt := time.Now()
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	if opts.Verbose {
		req = attachVerboseTrace(out, req, startedAt)
	}

	// Concurrent hold-poller: while client.Do is awaiting a response,
	// poll the daemon's /v1/holds and, if our in-flight request shows
	// up there, surface the hold id and the approve/deny commands so
	// the operator does not have to guess that the proxy is holding
	// the request. For held HTTPS CONNECT this is the only signal —
	// the proxy cannot return a 471 in-band on a tunnel that has not
	// been established yet (see issue #35).
	holdCtx, holdCancel := context.WithCancel(context.Background())
	defer holdCancel()
	go pollForHold(holdCtx, out, cfg, req)

	resp, err := client.Do(req)
	holdCancel()
	if err != nil {
		annotated := annotateRequestErr(err, proxyAddr, cfg.Interception.Enabled, req.URL.Scheme)
		printTestError(out, annotated, proxyAddr, cfg.Interception.Enabled, req.URL.Scheme)
		return &runtimeErr{annotated}
	}
	defer resp.Body.Close()

	bodyCap := int64(testBodyReadCap)
	if opts.Raw {
		bodyCap = testRawBodyCap
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, bodyCap))

	var dec *audit.Entry
	var decErr error
	if !opts.NoDecision {
		path := req.URL.Path
		if path == "" {
			path = "/"
		}
		dec, decErr = correlateDecision(
			cfg.Logging.AuditPath, startedAt,
			req.Method, req.URL.Hostname(), path,
			testCorrelationDeadlineMS*time.Millisecond,
		)
	}
	renderResult(out, req, proxyAddr, resp, bodyBytes, opts, dec, decErr)
	return nil
}

// printTestPreamble writes the "what we are about to do" block to out
// before client.Do fires. It runs even on the failure path, so when the
// daemon is down or the URL is wrong, the operator sees the attempted
// request, the proxy address, and which config file was loaded —
// without having to re-run with --verbose or read the source.
func printTestPreamble(out io.Writer, req *http.Request, proxyAddr, configPath, mode string, interceptionOn bool) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("trollbridge test:\n")
	w("  request:    %s %s\n", req.Method, req.URL.String())
	w("  via proxy:  %s\n", proxyAddr)
	cfgLine := configPath
	if cfgLine == "" {
		cfgLine = "(default)"
	}
	if mode != "" {
		cfgLine = fmt.Sprintf("%s (mode=%s, interception=%s)", cfgLine, mode, onOff(interceptionOn))
	}
	w("  config:     %s\n", cfgLine)
}

// printTestError emits an "error:" line plus one or more "hint:" lines
// pointing at the most likely operator next step for the failure shape.
// The wrapped error is returned upstream for exit-code routing; this
// function exists to give the operator a usable transcript on stdout.
func printTestError(out io.Writer, err error, proxyAddr string, interceptionOn bool, scheme string) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("  status:     -\n")
	w("  error:      %s\n", err.Error())
	for _, h := range testFailureHints(err, proxyAddr, interceptionOn, scheme) {
		w("  hint:       %s\n", h)
	}
}

// testFailureHints maps a Do() failure to one or more concrete
// operator hints. Tightly coupled to annotateRequestErr's substring
// classification (we already inspected the error there).
func testFailureHints(err error, proxyAddr string, interceptionOn bool, scheme string) []string {
	s := err.Error()
	switch {
	case strings.Contains(s, "cannot reach proxy at"):
		return []string{
			fmt.Sprintf("start the proxy: trollbridge run -c <path>"),
			fmt.Sprintf("verify the bind address: grep '^proxy:' trollbridge.yaml — current expectation is %s", proxyAddr),
		}
	case strings.Contains(s, "TLS handshake to upstream failed"):
		return []string{
			"interception is off; the test client's TLS session terminates at the upstream — install the upstream's CA into the client's system trust, or set interception.enabled: true and install trollbridge-ca.crt instead",
		}
	case strings.Contains(s, "TLS handshake failed"):
		return []string{
			"check that interception.enabled matches whether trollbridge-ca.crt is installed in this client's trust store",
		}
	case strings.Contains(s, "context deadline exceeded"), strings.Contains(s, "Client.Timeout"):
		return []string{
			"per-request timeout fired before a response. Raise --timeout, or check whether the upstream is reachable from the host running trollbridge run",
		}
	case strings.Contains(s, "EOF"), strings.Contains(s, "connection reset by peer"):
		return []string{
			fmt.Sprintf("the proxy at %s closed the connection unexpectedly. tail trollbridge run's stderr — a daemon panic or crash will appear there", proxyAddr),
		}
	}
	return []string{
		fmt.Sprintf("re-run with --no-decision to skip the audit-log read; if that succeeds the failure is not in the request path itself"),
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func annotateRequestErr(err error, proxyAddr string, interceptionOn bool, scheme string) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"), strings.Contains(s, "no such host"):
		return fmt.Errorf("cannot reach proxy at %s: %w; is `trollbridge run` running?", proxyAddr, err)
	case strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		if scheme == "https" && !interceptionOn {
			return fmt.Errorf("TLS handshake to upstream failed: %w; interception is disabled in trollbridge.yaml — the test client's TLS session is end-to-end with the upstream. Either enable interception, or trust the upstream's CA in your system store", err)
		}
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	return err
}

// attachVerboseTrace returns req with an httptrace.ClientTrace
// installed in its context that prints connection-level events
// to out as they fire. The events cover: DNS lookup, TCP connect,
// TLS handshake (peer name + version + cipher), wrote-headers,
// and first-byte. Times are deltas from startedAt for consistency
// with the existing preamble's wall-clock.
//
// On a proxied HTTPS request, the events that fire are for the
// proxy CONNECT — Go's stdlib httptrace does NOT see the inner
// upstream handshake when a proxy is in place. The header above
// the trace lines names that explicitly so the operator does not
// misread the timing.
func attachVerboseTrace(out io.Writer, req *http.Request, startedAt time.Time) *http.Request {
	var mu sync.Mutex
	headerPrinted := false
	w := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !headerPrinted {
			fmt.Fprintln(out, "  verbose:    (trace events below; under HTTPS via proxy these reflect the proxy CONNECT)")
			headerPrinted = true
		}
		fmt.Fprintf(out, "    "+format, a...)
	}
	since := func() time.Duration { return time.Since(startedAt).Round(time.Millisecond) }

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			w("dns_start      %s\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			ips := make([]string, 0, len(info.Addrs))
			for _, a := range info.Addrs {
				ips = append(ips, a.IP.String())
			}
			if info.Err != nil {
				w("dns_done       err=%v   t=%s\n", info.Err, since())
				return
			}
			w("dns_done       %s   t=%s\n", strings.Join(ips, ","), since())
		},
		ConnectStart: func(network, addr string) {
			w("connect_start  %s/%s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				w("connect_done   %s/%s err=%v   t=%s\n", network, addr, err, since())
				return
			}
			w("connect_done   %s/%s   t=%s\n", network, addr, since())
		},
		TLSHandshakeStart: func() {
			w("tls_start      t=%s\n", since())
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				w("tls_done       err=%v   t=%s\n", err, since())
				return
			}
			w("tls_done       version=%s cipher=%s server=%q   t=%s\n",
				tlsVersionName(state.Version), tls.CipherSuiteName(state.CipherSuite),
				state.ServerName, since())
		},
		WroteHeaders: func() {
			w("wrote_headers  t=%s\n", since())
		},
		GotFirstResponseByte: func() {
			w("first_byte     t=%s\n", since())
		},
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

// tlsVersionName turns the integer version into the operator-friendly
// label. Stdlib does not expose this directly via tls.VersionName as
// of Go 1.21; future versions may simplify this.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func loadInterceptionCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca: no PEM block found in %s", path)
	}
	return pool, nil
}

func renderResult(out io.Writer, req *http.Request, proxyAddr string, resp *http.Response, body []byte, opts testOpts, dec *audit.Entry, decErr error) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	// The "trollbridge test:" / "request:" / "via proxy:" preamble is
	// printed by printTestPreamble before client.Do, so the operator
	// sees what was attempted even when the call fails. renderResult
	// only emits the post-response section.
	w("  status:     %s\n", resp.Status)
	if r := resp.Header.Get("Trollbridge-Reason"); r != "" {
		w("  trollbridge: %s\n", r)
	}
	if v := resp.Header.Get("Via"); v != "" {
		w("  via:        %s\n", v)
	}

	switch {
	case opts.NoDecision:
		// skipped
	case decErr != nil:
		w("  decision:   unknown — %s\n", decErr.Error())
	case dec == nil:
		w("  decision:   unknown — no matching audit entry within deadline\n")
	default:
		w("  decision:   %s (source=%s rule=%s)\n",
			emptyToDash(dec.Decision),
			emptyToDash(dec.DecisionSource),
			emptyToDash(dec.RuleID))
		if dec.Reason != "" {
			w("  reason:     %s\n", dec.Reason)
		}
		if dec.LLMAdvisorID != "" {
			w("  advisor:    %s confidence=%s\n", dec.LLMAdvisorID, emptyToDash(dec.LLMConfidence))
		}
		if dec.LatencyMS > 0 {
			w("  latency:    %dms\n", dec.LatencyMS)
		}
	}

	if resp.StatusCode == 471 { // StatusTrollbridgePending — see internal/server/refusal.go
		holdID := extractHoldID(dec)
		if holdID != "" {
			w("  hint:       held — approve via `trollbridge approve %s`\n", holdID)
		} else {
			w("  hint:       held — list pending via `trollbridge decisions --pending`, then `trollbridge approve <id>`\n")
		}
	}
	// Closes #16: when the proxy declines a request, surface the
	// most likely operator next step — adding the host to the
	// allow list. We can give a host-specific recipe because the
	// request URL is in hand.
	if resp.StatusCode == 470 { // StatusTrollbridgeDeclined
		host := req.URL.Hostname()
		if host == "" {
			host = req.URL.Host
		}
		w("  hint:       declined — to allow this host, type in the `trollbridge run` REPL:\n")
		w("                  allow %s\n", host)
		w("              or add `%s` under lists.allow in trollbridge.yaml.\n", host)
	}

	if len(resp.Header) > 0 {
		keys := make([]string, 0, len(resp.Header))
		for k := range resp.Header {
			if k == "Trollbridge-Reason" || k == "Via" {
				continue
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			// MaxHeaders cap: the REPL's small console pane sets this
			// so 10+ response headers (Set-Cookie, Cache-Control,
			// X-Frame-Options, …) cannot scroll status / decision off
			// screen. Curate the most operator-useful keys first
			// (Content-Type, Content-Length), then alphabetical of the
			// remainder, up to the cap. The summary line names how many
			// were omitted.
			shown := keys
			omitted := 0
			if opts.MaxHeaders > 0 && len(keys) > opts.MaxHeaders {
				curated := []string{}
				rest := []string{}
				for _, k := range keys {
					if k == "Content-Type" || k == "Content-Length" {
						curated = append(curated, k)
					} else {
						rest = append(rest, k)
					}
				}
				// curated is already in alphabetical order because Content-Length < Content-Type lexicographically only if we re-sort; simpler: re-sort curated.
				sort.Strings(curated)
				cap := opts.MaxHeaders
				if len(curated) > cap {
					curated = curated[:cap]
				}
				room := cap - len(curated)
				if room > len(rest) {
					room = len(rest)
				}
				if room < 0 {
					room = 0
				}
				shown = append(curated, rest[:room]...)
				omitted = len(keys) - len(shown)
				sort.Strings(shown)
			}
			w("  headers:\n")
			for _, k := range shown {
				for _, v := range resp.Header.Values(k) {
					w("    %s: %s\n", k, v)
				}
			}
			if omitted > 0 {
				w("    (%d more headers omitted; run trollbridge test from a shell for full set)\n", omitted)
			}
		}
	}

	if opts.Raw {
		w("  body (%d bytes):\n", len(body))
		_, _ = out.Write(body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Fprintln(out)
		}
		return
	}
	if opts.ShowBody == 0 || len(body) == 0 {
		return
	}
	shown := body
	truncated := false
	if len(shown) > opts.ShowBody {
		shown = shown[:opts.ShowBody]
		truncated = true
	}
	if opts.MaxBodyLines > 0 {
		shown, truncated = capBodyLines(shown, opts.MaxBodyLines, truncated)
	}
	w("  body (%d bytes shown of %d):\n", len(shown), len(body))
	_, _ = out.Write(shown)
	if len(shown) > 0 && shown[len(shown)-1] != '\n' {
		fmt.Fprintln(out)
	}
	if truncated {
		w("  (truncated; use --raw or --show-body N to see more)\n")
	}
}

// capBodyLines trims a body byte slice to at most N newline-bounded
// lines, returning the new slice and a truncated flag that or's
// with whatever the caller already had. Used by the REPL test path
// to keep the response body from pushing status/decision lines off
// the small console pane.
func capBodyLines(body []byte, maxLines int, alreadyTruncated bool) ([]byte, bool) {
	if maxLines <= 0 || len(body) == 0 {
		return body, alreadyTruncated
	}
	count := 0
	for i, c := range body {
		if c == '\n' {
			count++
			if count >= maxLines {
				return body[:i+1], true
			}
		}
	}
	return body, alreadyTruncated
}

func emptyToDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func extractHoldID(dec *audit.Entry) string {
	if dec == nil {
		return ""
	}
	return dec.RequestID
}

// pollForHold watches the daemon's /v1/holds while client.Do is in
// flight and surfaces the matching hold to the operator the first
// time it appears. For HTTPS CONNECT under default-ask this is the
// only signal — the proxy holds the tunnel pre-200 and cannot
// return a 471 in-band; without this the test client just times
// out silently. The poller exits when ctx is cancelled (i.e. when
// the request returns or errors) or when it has surfaced once.
//
// Failures to reach the control plane are silent: the test command
// must continue to work on hosts without operator credentials.
func pollForHold(ctx context.Context, out io.Writer, cfg *config.Config, req *http.Request) {
	// Initial delay so we don't hit the control plane on every fast
	// request. 750ms is below the typical first-byte budget for a
	// LAN proxy and well below client.Timeout's default of 30s.
	select {
	case <-ctx.Done():
		return
	case <-time.After(750 * time.Millisecond):
	}

	host := req.URL.Hostname()
	port := holdPortFromURL(req.URL)
	wantConnect := strings.EqualFold(req.URL.Scheme, "https")
	wantMethod := strings.ToUpper(req.Method)

	tick := time.NewTicker(750 * time.Millisecond)
	defer tick.Stop()

	for {
		body, err := controlclient.Get(cfg, "/v1/holds")
		if err == nil {
			var holds []approvals.Snapshot
			if jerr := json.Unmarshal(body, &holds); jerr == nil {
				for _, h := range holds {
					if !holdMatches(h, host, port, wantConnect, wantMethod) {
						continue
					}
					fmt.Fprintf(out, "  held:       request held by proxy — id=%s\n", h.ID)
					fmt.Fprintf(out, "              approve via: trollbridge approve %s\n", h.ID)
					fmt.Fprintf(out, "              deny via:    trollbridge deny %s\n", h.ID)
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// holdPortFromURL returns the port the proxy will see in /v1/holds
// for req.URL. Empty Port() means the scheme default — 443 for HTTPS,
// 80 otherwise. Matches splitHostPort on the proxy side.
func holdPortFromURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// holdMatches reports whether snapshot h corresponds to the test
// request currently in flight. For HTTPS the proxy records the held
// CONNECT (Method="CONNECT", Scheme="https-tunneled"); for HTTP the
// proxy records the inner method (Method=req.Method, Scheme="http").
func holdMatches(h approvals.Snapshot, host string, port int, wantConnect bool, wantMethod string) bool {
	if !strings.EqualFold(h.Host, host) {
		return false
	}
	if h.Port != port {
		return false
	}
	if wantConnect {
		return strings.EqualFold(h.Method, "CONNECT")
	}
	return strings.EqualFold(h.Method, wantMethod)
}

// shellQuote wraps s in POSIX single quotes, escaping any internal
// single quote via the '\'' idiom. The result is safe to paste into
// bash, dash, or zsh: single quotes preserve every other character
// literally, including $, `, \, newlines, and shell metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// renderCurl writes two curl invocations to out: variant 1 with the
// proxy env embedded inline as a one-shot prefix (works in a fresh
// shell), and variant 2 bare (assumes `eval "$(trollbridge env)"`
// already ran in the caller's shell). Both variants are built from
// the same args list — single source of truth, no drift between them.
//
// proxyAddr is the form returned by cfg.Proxy.ClientAddr()
// (e.g. "127.0.0.1:8080" or "[::1]:8080"). body and bodyFile are the
// raw flag values; exactly one is non-empty (or both empty for no body).
func renderCurl(out io.Writer, req *http.Request, body, bodyFile, proxyAddr string) {
	args := buildCurlArgs(req, body, bodyFile)
	bare := "curl " + strings.Join(args, " ")
	proxyURL := "http://" + proxyAddr
	envPrefix := fmt.Sprintf("https_proxy=%s http_proxy=%s ",
		shellQuote(proxyURL), shellQuote(proxyURL))

	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("# trollbridge test --print-curl: equivalent curl command(s)\n")
	w("# variant 1 — proxy env embedded inline (works in a fresh shell)\n")
	w("%s%s\n", envPrefix, bare)
	w("\n")
	w("# variant 2 — bare (assumes you have already run: eval \"$(trollbridge env)\")\n")
	w("%s\n", bare)
}

// buildCurlArgs returns the per-flag tokens of the curl invocation,
// each already shell-quoted. GET is omitted (curl's default); other
// methods emit `-X METHOD`. Headers emit `-H 'KEY: VALUE'` in the
// order they were supplied. body becomes `--data-raw 'BODY'`;
// bodyFile becomes `--data-binary @'PATH'`. The URL is always last.
func buildCurlArgs(req *http.Request, body, bodyFile string) []string {
	var args []string
	if m := strings.ToUpper(req.Method); m != "" && m != http.MethodGet {
		args = append(args, "-X", shellQuote(m))
	}
	for _, k := range sortedHeaderKeys(req.Header) {
		for _, v := range req.Header.Values(k) {
			args = append(args, "-H", shellQuote(k+": "+v))
		}
	}
	switch {
	case body != "":
		args = append(args, "--data-raw", shellQuote(body))
	case bodyFile != "":
		args = append(args, "--data-binary", "@"+shellQuote(bodyFile))
	}
	args = append(args, shellQuote(req.URL.String()))
	return args
}

func sortedHeaderKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var errAuditNoMatch = errors.New("no match")

func correlateDecision(auditPath string, startedAt time.Time, method, host, urlPath string, deadline time.Duration) (*audit.Entry, error) {
	if auditPath == "" {
		return nil, errors.New("audit_path empty in config")
	}
	dl := time.Now().Add(deadline)
	for {
		entry, err := scanAuditTail(auditPath, startedAt, method, host, urlPath)
		if err == nil {
			return entry, nil
		}
		if !errors.Is(err, errAuditNoMatch) {
			return nil, fmt.Errorf("audit log not readable at %s: %w", auditPath, err)
		}
		if time.Now().After(dl) {
			return nil, errors.New("no matching audit entry within deadline")
		}
		time.Sleep(testCorrelationPollMS * time.Millisecond)
	}
}

func scanAuditTail(path string, startedAt time.Time, method, host, urlPath string) (*audit.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	off := int64(0)
	if size > testCorrelationScanWindowB {
		off = size - testCorrelationScanWindowB
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	earliest := startedAt.Add(-1 * time.Second)
	lines := bytes.Split(buf, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		if !strings.EqualFold(e.Method, method) {
			continue
		}
		if !strings.EqualFold(e.Host, host) {
			continue
		}
		ePath := e.Path
		if ePath == "" {
			ePath = "/"
		}
		if ePath != urlPath {
			continue
		}
		if e.Timestamp != "" {
			if ts, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
				if ts.Before(earliest) {
					continue
				}
			}
		}
		return &e, nil
	}
	return nil, errAuditNoMatch
}
