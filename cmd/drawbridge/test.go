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
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
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
	)
	cmd := &cobra.Command{
		Use:   "test <url>",
		Short: "Send a single request through the running proxy and print the proxy's decision plus the response.",
		Long: `Test sends one HTTP/HTTPS request through the running drawbridge
proxy (proxy address is read from drawbridge.yaml) and prints both
the proxy's decision (allow / deny / hold + matching rule, resolved
from the audit log) and the upstream response (status, selected
headers, body).

Examples:

  drawbridge test https://api.github.com/zen
  drawbridge test -X POST -H 'Content-Type: application/json' \
                  --body '{"q":"hi"}' https://api.openai.com/v1/chat/completions

For HTTPS URLs with TLS interception enabled, the test client
automatically trusts the configured drawbridge CA. With interception
disabled, the proxy is a transparent CONNECT tunnel and the test
client must already trust the upstream's certificate.

Held requests (under default-ask) return HTTP 511 with a
Drawbridge-Reason header; this command surfaces the hold and
the operator command needed to approve it.

Decision correlation reads the audit log named by drawbridge.yaml's
logging.audit_path. Under heavy concurrent traffic the matched
entry is "newest matching (method, host, path)"; for an idle proxy
this is unambiguous.

Use --print-curl to emit an equivalent curl command (two variants:
proxy env embedded inline, and bare) instead of sending the request.
The flag does not contact the proxy daemon; --show-body, --raw,
--timeout, and --no-decision do not apply under --print-curl.
The emitted curl command targets the proxy at the address from
drawbridge.yaml; the host that runs the curl command must share
network reachability with the daemon.`,
		Args: cobra.ExactArgs(1),
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
					return &configErr{fmt.Errorf("proxy is disabled in drawbridge.yaml (proxy: 0); set proxy: lo:8080 (or another bind) so --print-curl knows what proxy address to embed")}
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
			})
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "drawbridge.yaml path")
	cmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "extra request header (\"KEY: VALUE\"; repeatable)")
	cmd.Flags().StringVar(&body, "body", "", "request body (string)")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "request body (file path; mutually exclusive with --body)")
	cmd.Flags().IntVar(&showBody, "show-body", testDefaultBodyShow, "max bytes of response body to print (0 = none)")
	cmd.Flags().BoolVar(&raw, "raw", false, "print full response body, no truncation (suppresses --show-body)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", testDefaultTimeoutSec, "per-request timeout in seconds (0 = no timeout)")
	cmd.Flags().BoolVar(&noDecision, "no-decision", false, "skip audit-log decision correlation")
	cmd.Flags().BoolVar(&printCurl, "print-curl", false, "print an equivalent curl command (proxy env embedded, and bare) instead of sending the request")
	return cmd
}

type testOpts struct {
	ShowBody   int
	Raw        bool
	Timeout    time.Duration
	NoDecision bool
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
		return &configErr{fmt.Errorf("proxy is disabled in drawbridge.yaml (proxy: 0); set proxy: lo:8080 (or another bind) and run drawbridge run")}
	}
	proxyAddr := cfg.Proxy.ClientAddr()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return &configErr{fmt.Errorf("parse proxy addr %q: %w", proxyAddr, err)}
	}

	tlsCfg := &tls.Config{}
	if cfg.Interception.Enabled && cfg.Interception.CA.CertPath != "" {
		pool, perr := loadInterceptionCA(cfg.Interception.CA.CertPath)
		if perr == nil {
			tlsCfg.RootCAs = pool
		} else {
			fmt.Fprintf(os.Stderr, "drawbridge test: warning: configured interception CA at %s is unreadable (%v); falling back to system trust\n",
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

	startedAt := time.Now()
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	resp, err := client.Do(req)
	if err != nil {
		return &runtimeErr{annotateRequestErr(err, proxyAddr, cfg.Interception.Enabled, req.URL.Scheme)}
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

func annotateRequestErr(err error, proxyAddr string, interceptionOn bool, scheme string) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"), strings.Contains(s, "no such host"):
		return fmt.Errorf("cannot reach proxy at %s: %w; is `drawbridge run` running?", proxyAddr, err)
	case strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		if scheme == "https" && !interceptionOn {
			return fmt.Errorf("TLS handshake to upstream failed: %w; interception is disabled in drawbridge.yaml — the test client's TLS session is end-to-end with the upstream. Either enable interception, or trust the upstream's CA in your system store", err)
		}
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	return err
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
	w("drawbridge test:\n")
	w("  request:    %s %s\n", req.Method, req.URL.String())
	w("  via proxy:  %s\n", proxyAddr)
	w("  status:     %s\n", resp.Status)
	if r := resp.Header.Get("Drawbridge-Reason"); r != "" {
		w("  drawbridge: %s\n", r)
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

	if resp.StatusCode == http.StatusNetworkAuthenticationRequired {
		holdID := extractHoldID(dec)
		if holdID != "" {
			w("  hint:       held — approve via `drawbridge approve %s`\n", holdID)
		} else {
			w("  hint:       held — list pending via `drawbridge decisions --pending`, then `drawbridge approve <id>`\n")
		}
	}

	if len(resp.Header) > 0 {
		keys := make([]string, 0, len(resp.Header))
		for k := range resp.Header {
			if k == "Drawbridge-Reason" || k == "Via" {
				continue
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			w("  headers:\n")
			for _, k := range keys {
				for _, v := range resp.Header.Values(k) {
					w("    %s: %s\n", k, v)
				}
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
	w("  body (%d bytes shown of %d):\n", len(shown), len(body))
	_, _ = out.Write(shown)
	if len(shown) > 0 && shown[len(shown)-1] != '\n' {
		fmt.Fprintln(out)
	}
	if truncated {
		w("  (truncated; use --raw or --show-body N to see more)\n")
	}
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

// shellQuote wraps s in POSIX single quotes, escaping any internal
// single quote via the '\'' idiom. The result is safe to paste into
// bash, dash, or zsh: single quotes preserve every other character
// literally, including $, `, \, newlines, and shell metacharacters.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// renderCurl writes two curl invocations to out: variant 1 with the
// proxy env embedded inline as a one-shot prefix (works in a fresh
// shell), and variant 2 bare (assumes `eval "$(drawbridge env)"`
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
	w("# drawbridge test --print-curl: equivalent curl command(s)\n")
	w("# variant 1 — proxy env embedded inline (works in a fresh shell)\n")
	w("%s%s\n", envPrefix, bare)
	w("\n")
	w("# variant 2 — bare (assumes you have already run: eval \"$(drawbridge env)\")\n")
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
