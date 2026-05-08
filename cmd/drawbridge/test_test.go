package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
)

// minimalTestYaml writes a v3 drawbridge.yaml pointing the proxy at
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
	cfgPath = filepath.Join(dir, "drawbridge.yaml")
	body := strings.Join([]string{
		"drawbridge_version: 3",
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
// the drawbridge proxy*. The test client points its HTTP_PROXY at
// it; for plain HTTP requests through a forward proxy, the client
// sends `GET http://upstream/... HTTP/1.1` to the proxy, which lets
// us inspect and respond with arbitrary headers/body. This is
// sufficient to exercise the test command's rendering on plain HTTP.
func fakeOriginAsProxy(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
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
		w.Header().Set("Via", "1.1 drawbridge")
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
		"drawbridge test:",
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

func TestRunTest_DenyPath_RendersDrawbridgeReason(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Drawbridge-Reason", "deny: blocked by allowlist")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
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
		ResponseStatus: 403,
	})
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 4096}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"status:     403",
		"drawbridge: deny: blocked by allowlist",
		"decision:   deny (source=allowlist rule=-)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRunTest_HoldPath_511_SurfacesApproveHint(t *testing.T) {
	srv := fakeOriginAsProxy(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Drawbridge-Reason", "ask_user: needs approval")
		w.WriteHeader(http.StatusNetworkAuthenticationRequired)
		fmt.Fprint(w, "held")
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
		ResponseStatus: 511,
	})
	var buf bytes.Buffer
	if err := runTest(context.Background(), &buf, cfg, req, testOpts{ShowBody: 4096}); err != nil {
		t.Fatalf("runTest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "drawbridge approve hold-abc") {
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

func TestTestCmd_HelpListsFlags(t *testing.T) {
	cmd := newTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, want := range []string{"--method", "--header", "--body", "--show-body", "--raw", "--timeout", "--no-decision"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("--help missing %q", want)
		}
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
