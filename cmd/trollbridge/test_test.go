package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/ca"
	"github.com/dandriscoll/trollbridge/internal/config"
)

// minimalTestYaml writes a v3 trollbridge.yaml pointing the proxy at
// the given client-reachable host:port. The audit_path lives in the
// same temp dir; a caller can append fixture entries to it.
func minimalTestYaml(t *testing.T, proxyHost string, proxyPort int) (cfgPath, auditPath string) {
	t.Helper()
	dir := t.TempDir()
	auditPath = filepath.Join(dir, "audit.jsonl")
	host := proxyHost
	switch proxyHost {
	case "127.0.0.1":
		host = "lo"
	case "0.0.0.0":
		host = "all"
	}
	cfgPath = filepath.Join(dir, "trollbridge.yaml")
	body := strings.Join([]string{
		fmt.Sprintf("proxy: %s:%d", host, proxyPort),
		"control: 0",
		"controller: {auth: mtls}",
		"mode: default-deny",
		"approvals: {timeout_seconds: 60, on_timeout: deny, max_pending: 16}",
		"logging:",
		"  audit_path: " + auditPath,
		"  operational_path: " + filepath.Join(dir, "ops.log"),
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(auditPath, []byte{}, 0o600); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	return cfgPath, auditPath
}

func appendAuditEntry(t *testing.T, path string, e audit.Entry) {
	t.Helper()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		t.Fatal(err)
	}
}

// fakeOriginAsProxy is an httptest.Server that *acts as if it were
// the trollbridge proxy*. The test client points its HTTP_PROXY at
// it; for plain HTTP requests through a forward proxy, the client
// sends `GET http://upstream/... HTTP/1.1` to the proxy, which lets
// us inspect and respond with arbitrary headers/body. This is
// sufficient to exercise the test command's rendering on plain HTTP.
func fakeOriginAsProxy(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// TestCapBodyLines pins the line-cap behavior for the REPL's
// `test` command (closes #40). Pre-fix, `replTestFn` set
// ShowBody: 1024 with no line cap, so a chatty endpoint's body
// blew the operator's status/decision lines off the small
// console pane.
func TestCapBodyLines(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		max         int
		alreadyTrun bool
		wantBody    string
		wantTrun    bool
	}{
		{"empty body untouched", "", 3, false, "", false},
		{"max=0 untouched", "a\nb\nc\nd\n", 0, false, "a\nb\nc\nd\n", false},
		{"under cap untouched", "a\nb\n", 5, false, "a\nb\n", false},
		{"exactly cap untouched", "a\nb\nc\n", 3, false, "a\nb\nc\n", true},
		{"over cap truncates", "a\nb\nc\nd\ne\n", 3, false, "a\nb\nc\n", true},
		{"already truncated stays truncated", "a\nb\n", 5, true, "a\nb\n", true},
		{"long single line not split", "no newlines at all", 3, false, "no newlines at all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotTrun := capBodyLines([]byte(tc.body), tc.max, tc.alreadyTrun)
			if string(got) != tc.wantBody {
				t.Errorf("body = %q, want %q", got, tc.wantBody)
			}
			if gotTrun != tc.wantTrun {
				t.Errorf("truncated = %v, want %v", gotTrun, tc.wantTrun)
			}
		})
	}
}

func TestBuildTestRequest_FlagsAndHeaders(t *testing.T) {
	req, err := buildTestRequest("http://example.com/foo", "post",
		[]string{"X-A: one", "X-B:two", "Content-Type: application/json"},
		`{"k":1}`, "")
	if err != nil {
		t.Fatalf("buildTestRequest: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if got := req.Header.Get("X-A"); got != "one" {
		t.Errorf("X-A = %q", got)
	}
	if got := req.Header.Get("X-B"); got != "two" {
		t.Errorf("X-B = %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestBuildTestRequest_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name           string
		url            string
		method         string
		headers        []string
		body, bodyFile string
		wantSubstr     string
	}{
		{"no-scheme", "example.com/", "GET", nil, "", "", "URL must include scheme"},
		{"ftp-scheme", "ftp://example.com/", "GET", nil, "", "", "URL must include scheme"},
		{"empty-host", "http:///foo", "GET", nil, "", "", "missing host"},
		{"both-bodies", "http://example.com/", "POST", nil, "x", "/tmp/y", "mutually exclusive"},
		{"bad-header-no-colon", "http://example.com/", "GET", []string{"NoColon"}, "", "", "KEY: VALUE"},
		{"bad-header-empty-key", "http://example.com/", "GET", []string{": v"}, "", "", "empty key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildTestRequest(c.url, c.method, c.headers, c.body, c.bodyFile)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", c.wantSubstr)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantSubstr)
			}
		})
	}
}

func TestBuildTestRequest_StripsUserinfo(t *testing.T) {
	req, err := buildTestRequest("http://user:pw@example.com/", "GET", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.URL.String(), "user") || strings.Contains(req.URL.String(), "pw") {
		t.Errorf("userinfo leaked: %q", req.URL.String())
	}
}

func TestRunTest_ProxyDisabled_GuardedByRuntimeCheck(t *testing.T) {
	// config.Load rejects proxy: 0 today, so this is a defense-in-depth
	// guard. We construct the Config directly to exercise it without
	// going through the loader.
	cfg := &config.Config{}
	cfg.Proxy = config.Bind{Host: "lo", Port: 0}
	cfg.Logging.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	req, err := buildTestRequest("http://example.com/", "GET", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = runTest(context.Background(), &buf, cfg, req, testOpts{})
	var ce *configErr
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v (%T), want configErr", err, err)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("err = %q, want 'disabled'", err.Error())
	}
}

func TestRunTest_AllowPath_RendersDecisionAndResponse(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 trollbridge")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello world")
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, auditPath := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, err := buildTestRequest("http://api.example.com/foo", "GET", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	appendAuditEntry(t, auditPath, audit.Entry{
		RequestID: "req-1", Method: "GET", Host: "api.example.com", Path: "/foo",
		Decision: "allow", DecisionSource: "rule", RuleID: "r-allow-github", Reason: "matched",
		ResponseStatus: 200, LatencyMS: 12,
	})

	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 4096}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"trollbridge test:",
		"GET http://api.example.com/foo",
		"status:     200",
		"decision:   allow (source=rule rule=r-allow-github)",
		"reason:     matched",
		"latency:    12ms",
		"hello world",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<no value>") || strings.Contains(out, "<nil>") {
		t.Errorf("output has Go fmt sentinel:\n%s", out)
	}
}

func TestRunTest_DenyPath_RendersTrollbridgeReason(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		// New wire contract (issue #11): 470, categorical Trollbridge-Reason.
		w.Header().Set("Trollbridge-Reason", "declined")
		w.WriteHeader(470)
		fmt.Fprint(w, "trollbridge: request declined")
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, auditPath := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://forbidden.example/", "GET", nil, "", "")
	appendAuditEntry(t, auditPath, audit.Entry{
		Method: "GET", Host: "forbidden.example", Path: "/",
		Decision: "deny", DecisionSource: "allowlist", Reason: "not in allow",
		ResponseStatus: 470,
	})
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 4096}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"status:     470",
		"trollbridge: declined",
		"decision:   deny (source=allowlist rule=-)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestRunTest_DeclinedPath_470_SurfacesAllowHint closes issue #16:
// when the proxy declines a request (HTTP 470), the test command
// should suggest adding the host to the allow list — the most
// likely operator next step for a first-time decline.
func TestRunTest_DeclinedPath_470_SurfacesAllowHint(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trollbridge-Reason", "declined")
		w.WriteHeader(470)
		fmt.Fprint(w, "trollbridge: request declined")
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, auditPath := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://forbidden.example/", "GET", nil, "", "")
	appendAuditEntry(t, auditPath, audit.Entry{
		Method: "GET", Host: "forbidden.example", Path: "/",
		Decision: "deny", DecisionSource: "default", Reason: "default-deny",
		ResponseStatus: 470,
	})
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 0}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"hint:       declined",
		"allow forbidden.example",
		"lists.allow",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in 470-decline transcript:\n%s", want, out)
		}
	}
}

// TestHoldMatches covers the matching predicate used by pollForHold:
// HTTPS in-flight requests match the proxy's CONNECT hold; HTTP
// in-flight requests match the inner method. Closes issue #35's
// matching contract.
func TestHoldMatches(t *testing.T) {
	connectHold := approvals.Snapshot{Method: "CONNECT", Scheme: "https-tunneled", Host: "github.com", Port: 443}
	httpHold := approvals.Snapshot{Method: "GET", Scheme: "http", Host: "api.example.com", Port: 80}
	otherHostHold := approvals.Snapshot{Method: "CONNECT", Scheme: "https-tunneled", Host: "other.example", Port: 443}

	cases := []struct {
		name        string
		h           approvals.Snapshot
		host        string
		port        int
		wantConnect bool
		wantMethod  string
		want        bool
	}{
		{"https request matches connect hold", connectHold, "github.com", 443, true, "GET", true},
		{"https request mismatches host", connectHold, "elsewhere.com", 443, true, "GET", false},
		{"https request mismatches port", connectHold, "github.com", 8443, true, "GET", false},
		{"https request rejects http hold for same host", httpHold, "api.example.com", 80, true, "GET", false},
		{"http get matches inner method", httpHold, "api.example.com", 80, false, "GET", true},
		{"http get rejects connect hold", connectHold, "github.com", 443, false, "GET", false},
		{"http post mismatches get", httpHold, "api.example.com", 80, false, "POST", false},
		{"https request rejects unrelated host", otherHostHold, "github.com", 443, true, "GET", false},
		{"case-insensitive host", connectHold, "GitHub.com", 443, true, "GET", true},
		{"case-insensitive method", httpHold, "api.example.com", 80, false, "get", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := holdMatches(tc.h, tc.host, tc.port, tc.wantConnect, tc.wantMethod)
			if got != tc.want {
				t.Errorf("holdMatches(%+v, %q, %d, %v, %q) = %v, want %v",
					tc.h, tc.host, tc.port, tc.wantConnect, tc.wantMethod, got, tc.want)
			}
		})
	}
}

// TestHoldPortFromURL covers the scheme-default behaviour pollForHold
// uses to determine the proxy's recorded port.
func TestHoldPortFromURL(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"https://github.com/", 443},
		{"http://github.com/", 80},
		{"https://github.com:8443/", 8443},
		{"http://github.com:8080/", 8080},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := holdPortFromURL(u); got != tc.want {
				t.Errorf("holdPortFromURL(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

// TestPollForHold_ExitsOnContextCancel verifies pollForHold does
// not leak when the surrounding request returns before a hold is
// surfaced. The failure mode this catches: a goroutine that keeps
// hitting the control plane after the test command has already
// rendered its result.
func TestPollForHold_ExitsOnContextCancel(t *testing.T) {
	// Point controller-cert env vars at non-existent paths so
	// controlclient.Get errors immediately on every tick. pollForHold
	// must still exit cleanly when ctx is cancelled.
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/nonexistent/cert")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "/nonexistent/key")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "/nonexistent/ca")

	cfgPath, _ := minimalTestYaml(t, "127.0.0.1", 1)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, err := buildTestRequest("https://github.com/", "GET", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		var buf bytes.Buffer
		pollForHold(ctx, &buf, cfg, req)
		close(done)
	}()
	// Cancel before the initial 750ms delay elapses; pollForHold
	// must return promptly.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pollForHold did not exit after context cancel")
	}
}

func TestRunTest_HoldPath_471_SurfacesApproveHint(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		// New wire contract (issue #11): 471, categorical Trollbridge-Reason.
		w.Header().Set("Trollbridge-Reason", "pending")
		w.WriteHeader(471)
		fmt.Fprint(w, "trollbridge: request pending approval")
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, auditPath := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://held.example/x", "GET", nil, "", "")
	appendAuditEntry(t, auditPath, audit.Entry{
		RequestID: "hold-abc", Method: "GET", Host: "held.example", Path: "/x",
		Decision: "ask_user", DecisionSource: "default", Reason: "default-ask",
		ResponseStatus: 471,
	})
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 4096}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "trollbridge approve hold-abc") {
		t.Errorf("expected approve hint with hold-abc; got:\n%s", out)
	}
}

func TestRunTest_AuditMissing_DegradesGracefully(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, auditPath := minimalTestYaml(t, host, port)
	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://x.example/", "GET", nil, "", "")
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 0}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "decision:   unknown") {
		t.Errorf("expected graceful unknown-decision; got:\n%s", out)
	}
	if !strings.Contains(out, "audit log not readable") {
		t.Errorf("expected audit-not-readable explanation; got:\n%s", out)
	}
}

func TestRunTest_NoDecisionFlag_SkipsCorrelation(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	cfgPath, _ := minimalTestYaml(t, host, port)
	cfg, _ := config.Load(cfgPath)
	req, _ := buildTestRequest("http://x.example/", "GET", nil, "", "")
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{NoDecision: true, ShowBody: 0}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "decision:") {
		t.Errorf("--no-decision should suppress decision line:\n%s", buf.String())
	}
}

func TestScanAuditTail_NewestMatchingWins(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entries := []audit.Entry{
		{Method: "GET", Host: "x.example", Path: "/", Decision: "allow", RuleID: "old", Timestamp: now.Add(-10 * time.Second).Format(time.RFC3339Nano)},
		{Method: "GET", Host: "y.example", Path: "/", Decision: "allow", RuleID: "wrong-host", Timestamp: now.Format(time.RFC3339Nano)},
		{Method: "GET", Host: "x.example", Path: "/", Decision: "deny", RuleID: "newer", Timestamp: now.Format(time.RFC3339Nano)},
	}
	for _, e := range entries {
		appendAuditEntry(t, p, e)
	}
	got, err := scanAuditTail(p, now.Add(-1*time.Second), "GET", "x.example", "/")
	if err != nil {
		t.Fatalf("scanAuditTail: %v", err)
	}
	if got.RuleID != "newer" {
		t.Errorf("RuleID = %q, want %q", got.RuleID, "newer")
	}
}

func TestScanAuditTail_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	body := "garbage\n" +
		"{\"method\":\"GET\",\"host\":\"a.example\",\"path\":\"/\",\"decision\":\"allow\",\"timestamp\":\"" + now + "\"}\n" +
		"{not json\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := scanAuditTail(p, time.Now().Add(-time.Hour), "GET", "a.example", "/")
	if err != nil {
		t.Fatalf("scanAuditTail: %v", err)
	}
	if got.Decision != "allow" {
		t.Errorf("Decision = %q", got.Decision)
	}
}

func TestScanAuditTail_NoMatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	if err := os.WriteFile(p, []byte("{\"method\":\"GET\",\"host\":\"other\",\"path\":\"/\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := scanAuditTail(p, time.Now().Add(-time.Hour), "GET", "x.example", "/")
	if !errors.Is(err, errAuditNoMatch) {
		t.Errorf("err = %v, want errAuditNoMatch", err)
	}
}

func TestRender_NoFmtSentinels_OnEmptyEntry(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://x.example/", nil)
	resp := &http.Response{
		Status: "200 OK", StatusCode: 200,
		Header: http.Header{},
	}
	resp.Body = http.NoBody
	var buf bytes.Buffer
	renderResult(&buf, req, "127.0.0.1:8080", resp, nil, testOpts{ShowBody: 4096}, &audit.Entry{}, nil)
	out := buf.String()
	if strings.Contains(out, "<no value>") || strings.Contains(out, "<nil>") {
		t.Errorf("fmt sentinel in:\n%s", out)
	}
	if !strings.Contains(out, "decision:   - (source=- rule=-)") {
		t.Errorf("expected dash-filled decision line; got:\n%s", out)
	}
}

// TestTestCmd_NoArgs_ShowsUsageAndExamples closes issue #13: when
// `trollbridge test` is run without a URL, the user gets a usage block
// with concrete examples — not just cobra's terse "accepts 1 arg(s)".
func TestTestCmd_NoArgs_ShowsUsageAndExamples(t *testing.T) {
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from missing positional arg")
	}
	msg := err.Error()
	for _, want := range []string{
		"takes one URL argument",
		"Usage:",
		"trollbridge test [flags] <url>",
		"Examples:",
		"https://api.github.com/zen",
		"--print-curl",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("usage message missing %q in:\n%s", want, msg)
		}
	}
}

// TestTestCmd_TooManyArgs_ShowsUsage closes the second branch of
// requireURLArg.
func TestTestCmd_TooManyArgs_ShowsUsage(t *testing.T) {
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"http://a/", "http://b/"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for >1 positional args")
	}
	if !strings.Contains(err.Error(), "got 2") {
		t.Errorf("expected 'got 2' in error; got: %v", err)
	}
}

// TestRunTest_FailedDial_PrintsPreambleAndHint closes issue #13's
// second branch: when client.Do fails (proxy unreachable), the
// operator sees the preamble (so they know what was attempted) plus an
// error: line and a hint: line pointing at the next operator step.
func TestRunTest_FailedDial_PrintsPreambleAndHint(t *testing.T) {
	// Allocate a TCP listener and immediately close it to get a
	// reliably-unreachable port (less flaky than picking 1).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfgPath, _ := minimalTestYaml(t, "127.0.0.1", closedPort)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://api.example.com/foo", "GET", nil, "", "")

	var buf bytes.Buffer
	runErr := runTest(context.Background(), &buf, cfg, req,
		testOpts{ShowBody: 0, Timeout: 2 * time.Second, ConfigPath: cfgPath})
	if runErr == nil {
		t.Fatal("expected error from closed-port dial")
	}
	out := buf.String()
	for _, want := range []string{
		"trollbridge test:",
		"GET http://api.example.com/foo",
		"via proxy:",
		"config:",
		"error:",
		"hint:",
		"trollbridge run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in failure transcript:\n%s", want, out)
		}
	}
}

// (annotateConfigLoadErr was inlined into internal/config.Load —
// issue #27 — so all callers benefit. The contract test now lives
// at internal/config TestLoad_FileNotFound_NamesInitCommand.)

func TestTestCmd_HelpListsFlags(t *testing.T) {
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, want := range []string{"--method", "--header", "--body", "--show-body", "--raw", "--timeout", "--no-decision", "--print-curl", "--ca-file", "--cacert", "--verbose"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("--help missing %q", want)
		}
	}
}

// TestRunTest_CAFile_Override closes issue #32: when --ca-file is set,
// the test client uses that CA for HTTPS verification regardless of
// cfg.Interception.Enabled. We verify the wiring by passing a
// nonexistent path and asserting the error names --ca-file (so the
// operator can disambiguate from a config-derived CA load).
func TestRunTest_CAFile_NotFound_ErrorNamesFlag(t *testing.T) {
	cfgPath, _ := minimalTestYaml(t, "127.0.0.1", 1)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("https://example.com/", "GET", nil, "", "")
	var buf bytes.Buffer
	err = runTest(context.Background(), &buf, cfg, req,
		testOpts{CAFile: "/nonexistent/ca.crt", Timeout: 1 * time.Second})
	if err == nil {
		t.Fatal("expected error from --ca-file pointing at missing file")
	}
	if !strings.Contains(err.Error(), "--ca-file") {
		t.Errorf("error should name --ca-file so the operator knows the source: %v", err)
	}
}

// TestRunTest_CAFile_PreambleSurfacesPath: when --ca-file loads, the
// preamble names the resolved CA path so the operator does not have
// to re-run with -v to know which CA the test client trusted.
func TestRunTest_CAFile_PreambleSurfacesPath(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, _ := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write a real PEM-shaped (but otherwise stub) cert so the loader
	// accepts it. We use a self-signed leaf for content-only purposes.
	caPath := filepath.Join(t.TempDir(), "operator-ca.crt")
	if err := os.WriteFile(caPath, fixtureSelfSignedCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://x.example/", "GET", nil, "", "")
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req,
		testOpts{CAFile: caPath, NoDecision: true, ShowBody: 0}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ca-file:") {
		t.Errorf("preamble missing ca-file line:\n%s", out)
	}
	if !strings.Contains(out, caPath) {
		t.Errorf("preamble does not name the resolved CA path %q:\n%s", caPath, out)
	}
	// interception is off in the test config — note must be present
	if !strings.Contains(out, "interception is off") {
		t.Errorf("preamble note about interception-off should fire:\n%s", out)
	}
}

// TestRunTest_Verbose_AttachesTraceEvents closes issue #33: --verbose
// emits connection-level events. We exercise the plain-HTTP path
// against the fake-proxy server and assert at least one trace line
// (DNS or connect) shows up before the response.
func TestRunTest_Verbose_AttachesTraceEvents(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	cfgPath, _ := minimalTestYaml(t, host, port)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := buildTestRequest("http://x.example/", "GET", nil, "", "")
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req,
		testOpts{Verbose: true, NoDecision: true, ShowBody: 0}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "verbose:") {
		t.Errorf("verbose header missing:\n%s", out)
	}
	// At least one of the connection-level events should fire on a
	// real net.Dial against the fake server.
	any := false
	for _, want := range []string{"connect_start", "connect_done", "wrote_headers", "first_byte"} {
		if strings.Contains(out, want) {
			any = true
			break
		}
	}
	if !any {
		t.Errorf("expected at least one trace event in:\n%s", out)
	}
}

func TestTestCmd_ConflictingBodyFlags(t *testing.T) {
	cfgPath, _ := minimalTestYaml(t, "127.0.0.1", 1) // any addr; we won't reach the request stage
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"-c", cfgPath, "--body", "x", "--body-file", "/dev/null", "http://x.example/"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("want error")
	}
	var ce *configErr
	if !errors.As(err, &ce) {
		t.Errorf("err = %v (%T), want configErr", err, err)
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "''"},
		{"plain", "'plain'"},
		{"a b c", "'a b c'"},
		{"it's", `'it'\''s'`},
		{"''", `''\'''\'''`},
		{`$VAR`, `'$VAR'`},
		{"`backtick`", "'`backtick`'"},
		{`back\slash`, `'back\slash'`},
		{"new\nline", "'new\nline'"},
		{`;|&()<>`, `';|&()<>'`},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := shellQuote(c.in); got != c.want {
				t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRenderCurl_GET_NoBody(t *testing.T) {
	req, err := buildTestRequest("https://api.github.com/zen", "GET", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderCurl(&buf, req, "", "", "127.0.0.1:8080")
	got := buf.String()
	want := "# trollbridge test --print-curl: equivalent curl command(s)\n" +
		"# variant 1 — proxy env embedded inline (works in a fresh shell)\n" +
		"https_proxy='http://127.0.0.1:8080' http_proxy='http://127.0.0.1:8080' curl 'https://api.github.com/zen'\n" +
		"\n" +
		"# variant 2 — bare (assumes you have already run: eval \"$(trollbridge env)\")\n" +
		"curl 'https://api.github.com/zen'\n"
	if got != want {
		t.Errorf("renderCurl GET mismatch.\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderCurl_POST_HeadersAndBody(t *testing.T) {
	req, err := buildTestRequest(
		"https://api.openai.com/v1/x", "POST",
		[]string{"Content-Type: application/json", "Authorization: Bearer abc"},
		`{"q":"hi"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderCurl(&buf, req, `{"q":"hi"}`, "", "127.0.0.1:8080")
	got := buf.String()
	for _, want := range []string{
		"-X 'POST'",
		"-H 'Authorization: Bearer abc'",
		"-H 'Content-Type: application/json'",
		`--data-raw '{"q":"hi"}'`,
		"'https://api.openai.com/v1/x'",
		"https_proxy='http://127.0.0.1:8080' http_proxy='http://127.0.0.1:8080' curl ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// header sort ordering: Authorization should appear before Content-Type
	if idxA, idxC := strings.Index(got, "Authorization"), strings.Index(got, "Content-Type"); idxA == -1 || idxC == -1 || idxA > idxC {
		t.Errorf("expected Authorization before Content-Type:\n%s", got)
	}
}

func TestRenderCurl_BodyFile(t *testing.T) {
	dir := t.TempDir()
	bodyFile := filepath.Join(dir, "with space", "payload.json")
	if err := os.MkdirAll(filepath.Dir(bodyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bodyFile, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := buildTestRequest("http://x.example/upload", "POST", nil, "", bodyFile)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderCurl(&buf, req, "", bodyFile, "127.0.0.1:8080")
	got := buf.String()
	wantToken := "--data-binary @" + shellQuote(bodyFile)
	if !strings.Contains(got, wantToken) {
		t.Errorf("expected %q in output; got:\n%s", wantToken, got)
	}
	if strings.Contains(got, "--data-raw") {
		t.Errorf("--body-file should not produce --data-raw:\n%s", got)
	}
}

func TestRenderCurl_QuotingHazards(t *testing.T) {
	req, err := buildTestRequest(
		"https://x.example/?q='hi'", "POST",
		[]string{`X-Note: it's "fine"`},
		`a'b$c;|&`, "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderCurl(&buf, req, `a'b$c;|&`, "", "127.0.0.1:8080")
	got := buf.String()
	for _, want := range []string{
		`'https://x.example/?q='\''hi'\'''`,                // url
		`-H 'X-Note: it'\''s "fine"'`,                      // header
		`--data-raw 'a'\''b$c;|&'`,                          // body
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing escaped form %q in:\n%s", want, got)
		}
	}
}

func TestRenderCurl_BothVariantsBuiltFromSameArgs(t *testing.T) {
	req, err := buildTestRequest("http://x.example/", "POST",
		[]string{"X-A: one"}, "body", "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderCurl(&buf, req, "body", "", "127.0.0.1:8080")
	out := buf.String()
	envPrefix := "https_proxy='http://127.0.0.1:8080' http_proxy='http://127.0.0.1:8080' "
	// extract variant-1 line (after first variant comment)
	v1Header := "# variant 1 — proxy env embedded inline (works in a fresh shell)\n"
	v2Header := "# variant 2 — bare (assumes you have already run: eval \"$(trollbridge env)\")\n"
	v1Start := strings.Index(out, v1Header) + len(v1Header)
	v1End := strings.Index(out[v1Start:], "\n") + v1Start
	v2Start := strings.Index(out, v2Header) + len(v2Header)
	v2End := strings.Index(out[v2Start:], "\n") + v2Start
	v1, v2 := out[v1Start:v1End], out[v2Start:v2End]
	if got, want := strings.TrimPrefix(v1, envPrefix), v2; got != want {
		t.Errorf("variant 1 minus env prefix should equal variant 2.\n v1-prefix=%q\n      v2=%q", got, want)
	}
}

func TestTestCmd_PrintCurl_NoDaemonNeeded(t *testing.T) {
	// Point proxy at a closed port; --print-curl must not dial.
	cfgPath, _ := minimalTestYaml(t, "127.0.0.1", 1)
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"-c", cfgPath, "--print-curl", "http://example.com/path"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--print-curl must not contact the daemon; got err: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "curl 'http://example.com/path'") {
		t.Errorf("expected bare curl line; got:\n%s", out)
	}
	if !strings.Contains(out, "https_proxy='http://127.0.0.1:1'") {
		t.Errorf("expected env-prefix line with proxy URL; got:\n%s", out)
	}
}

// fixtureSelfSignedCA generates a fresh CA via the internal/ca
// package and returns its PEM-encoded cert bytes. Suitable for
// passing to runTest as the --ca-file value when the test only
// needs a parseable PEM (not a chain that validates an upstream).
func fixtureSelfSignedCA(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := ca.Init(certPath, keyPath, ca.KeyTypeECDSAP256, false); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

func splitHostPort(t *testing.T, urlStr string) (string, int) {
	t.Helper()
	u, err := url.Parse(urlStr)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	var port int
	if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil {
		t.Fatalf("port parse: %v", err)
	}
	return host, port
}
