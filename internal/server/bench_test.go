package server

import (
	"context"
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

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/policy"
)

// BenchmarkPlainHTTP_ProxyOverhead measures the per-request latency
// added by drawbridge for an allow-by-rule plain HTTP request to a
// localhost stub origin. The DESIGN.md §11 / §19.5 claim is < 5ms
// p95 on localhost. We don't compute p95 here; we report ns/op and
// let the operator interpret.
func BenchmarkPlainHTTP_ProxyOverhead(b *testing.B) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "x")
	}))
	defer origin.Close()
	originHost, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	dir := b.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	rules := fmt.Sprintf(`
- id: a
  match: {host: %s}
  effect: allow
`, originHost)
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg := &config.Config{
		Mode:      "default-deny",
		Logging:   config.Logging{AuditPath: auditPath, AuditBufferSize: 1024, AuditOverflow: "drop"},
		Forwarder: config.Forwarder{MaxIdleConns: 256, MaxIdleConnsPerHost: 32, ConnectionAcquireTimeoutSeconds: 5},
		Shutdown:  config.Shutdown{GraceSeconds: 5},
		Identities: []config.Identity{{ID: "test", Match: config.IdentityMatch{SourceIP: "127.0.0.1"}}},
		Policy:     config.Policy{Include: []string{rulesPath}},
	}
	engine, err := policy.NewEngine(cfg.Mode, []string{rulesPath}, policy.KnownModifiers())
	if err != nil {
		b.Fatal(err)
	}
	logger, err := audit.New(auditPath, 1024, audit.OverflowDrop)
	if err != nil {
		b.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, logger)
	if err != nil {
		b.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.ServeOnListener(ctx, ln)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(origin.URL)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
