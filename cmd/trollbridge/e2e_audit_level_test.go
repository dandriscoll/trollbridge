//go:build e2e

// E2E coverage for `audit_level: decisions` (#161). Wires the
// config-loader → audit filter → on-disk-log path end-to-end. The
// filter is covered at the unit-test layer; this lane catches the
// regression where the cobra wiring or server bootstrap fails to
// call SetLevel(). A request matching the allowlist (static-policy
// source) must NOT land in the audit log when audit_level=decisions.

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_AuditLevel_DecisionsFiltersStaticPolicy(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	upHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	auditPath := filepath.Join(dir, "audit.jsonl")
	yamlPath := filepath.Join(dir, "trollbridge.yaml")
	yaml := fmt.Sprintf(`proxy: lo:%d
control: 0
metrics: 0
mode: default-deny
lists:
  allow:
    - %s
  deny: []
logging:
  audit_path:       %s
  audit_overflow:   deny
  operational_path: stderr
  audit_level:      decisions
approvals:
  timeout_seconds: 60
  on_timeout: deny
  max_pending: 16
interception:
  enabled: false
`, port, upHost, auditPath)
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	// Issue the allowlist-matched request; the daemon allows and
	// proxies it to the upstream. The matching audit entry's
	// DecisionSource is SourceAllowList — static-policy. With
	// audit_level=decisions, the entry must NOT appear in the
	// audit log.
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected proxy response: status=%d body=%q", resp.StatusCode, body)
	}

	// Audit is async-buffered; give it a moment to flush, then
	// scan. The allowlist entry MUST be absent — if it appears,
	// the filter wasn't engaged.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(auditPath)
		if err == nil && len(b) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := os.ReadFile(auditPath)
	contents := string(b)
	if strings.Contains(contents, `"decision_source":"allowlist"`) {
		t.Errorf("audit_level=decisions leaked an allowlist entry into the log:\n%s", contents)
	}
	// Sanity: the file may be empty (decisions filtered out the
	// only entry) — that's expected here. The negative-only
	// assertion is the load-bearing claim.
}
