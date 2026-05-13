//go:build e2e

// E2E test: external edits to trollbridge.yaml trigger an in-process
// reload of allow/deny lists. Closes #103 part 3.
//
// Why this test: the existing configwatch_test.go covers the watcher
// at the unit level; rule_reload_test.go and configwrite tests cover
// the engine's reload path. Nothing exercises the wired chain from
// "external editor saves trollbridge.yaml" to "next request through
// the proxy honors the new lists" against the real binary.
//
// The test uses synthetic hostnames (never resolved) and asserts on
// the audit log's decision field rather than wire success — the
// audit records the proxy's policy decision before any upstream
// dial, so we can observe the allowlist taking effect without
// needing real upstream services.
//
// Run with:
//
//	go test -tags=e2e ./cmd/trollbridge/... -run TestE2E_HotReload

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_HotReload_ExternalEditTakesEffect(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)

	auditPath := filepath.Join(dir, "audit.jsonl")
	yamlPath := filepath.Join(dir, "trollbridge.yaml")

	body := func(allow []string) string {
		var allowBlock string
		for _, h := range allow {
			allowBlock += "    - " + h + "\n"
		}
		return fmt.Sprintf(`proxy:   lo:%d
control: 0
metrics: 0
controller: {auth: mtls}
mode: default-deny
lists:
  allow:
%s  deny: []
logging:
  audit_path:        %s
  audit_overflow:    deny
  operational_path:  stderr
approvals:
  timeout_seconds: 5
  on_timeout: deny
  max_pending: 16
interception:
  enabled: false
`, port, allowBlock, auditPath)
	}

	if err := os.WriteFile(yamlPath, []byte(body([]string{"allowed-pre.test"})), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stop := startDaemon(t, yamlPath)
	defer stop()
	waitForProxyBind(t, port)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	dial := &net.Dialer{Timeout: 200 * time.Millisecond}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			DisableKeepAlives:   true,
			DialContext:         dial.DialContext,
			ResponseHeaderTimeout: 2 * time.Second,
		},
		Timeout: 3 * time.Second,
	}

	// Pre-reload: allowed-pre.test is allowed; allowed-post.test is
	// denied (default-deny + not on the list). The audit records the
	// decision before the proxy dials upstream, so the forward
	// failing on a non-resolvable hostname does not affect the
	// decision recorded.
	_, _ = client.Get("http://allowed-pre.test/")
	resp, err := client.Get("http://allowed-post.test/")
	if err != nil {
		t.Fatalf("pre-reload GET allowed-post.test: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 470 {
		t.Fatalf("pre-reload GET allowed-post.test: status=%d, want 470 (default-deny)", resp.StatusCode)
	}

	// Externally edit trollbridge.yaml to also allow allowed-post.test.
	// Sleep briefly so the new mtime is detectable on coarse-grained
	// filesystems (HFS+ on macOS has 1s mtime granularity).
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(yamlPath, []byte(body([]string{"allowed-pre.test", "allowed-post.test"})), 0o600); err != nil {
		t.Fatal(err)
	}

	// Poll until the allowlist takes effect: send GET to
	// allowed-post.test until the audit shows an allow decision.
	deadline := time.Now().Add(8 * time.Second)
	postReloadOK := false
	for time.Now().Before(deadline) {
		_, _ = client.Get("http://allowed-post.test/")
		// Check the audit log for an allow on allowed-post.test.
		data, err := os.ReadFile(auditPath)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, `"host":"allowed-post.test"`) &&
					strings.Contains(line, `"decision":"allow"`) {
					postReloadOK = true
					break
				}
			}
		}
		if postReloadOK {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !postReloadOK {
		audit, _ := os.ReadFile(auditPath)
		t.Fatalf("audit never showed an allow for allowed-post.test after 8s\naudit:\n%s", audit)
	}
}
