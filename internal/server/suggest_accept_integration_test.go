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

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/suggestion"
)

// --- suggestion.Manager wiring, mirroring cmd/trollbridge's adapters
// but exercising the REAL configwrite + a REAL server reload, so the
// accept path is tested end-to-end (#204): write rule → reload config →
// matcher recompiles → next request is matched.

type fileLists struct{ path string }

func (f fileLists) CurrentLists() ([]string, []string, []config.DeclinedSuggestion) {
	c, err := config.Load(f.path)
	if err != nil {
		return nil, nil, nil
	}
	return c.Lists.Allow, c.Lists.Deny, c.Lists.DeclinedSuggestions
}

type realWriter struct{}

func (realWriter) Generalize(path, list, pat string, sources []string) (bool, error) {
	return configwrite.Generalize(path, list, pat, sources)
}
func (realWriter) AddDeclinedSuggestion(path string, src, axes []string, at string) (bool, error) {
	return configwrite.AddDeclinedSuggestion(path, configwrite.DeclinedSuggestion{
		SourceEntries: src, AxesDeclined: axes, DeclinedAt: at,
	})
}
func (realWriter) AcceptPatternSuggestion(rulesPath, listsPath, list, ruleID, pattern string, components map[string]string, method, effect string, sources []string) (bool, bool, error) {
	return configwrite.AcceptPatternSuggestion(rulesPath, listsPath, list, configwrite.PatternRule{
		ID: ruleID, Pattern: pattern, Components: components, Method: method, Effect: effect,
	}, sources)
}

type emptyQueue struct{}

func (emptyQueue) Pending() []suggestion.QueueSnapshot { return nil }

// rankingAdvisor ranks by the (deterministic) order of axes present in
// the candidate set — enough to drive Manager.produce to an offer.
type rankingAdvisor struct{}

func (rankingAdvisor) Suggest(_ context.Context, in advisor.SuggestionInput) (advisor.SuggestionOutput, time.Duration, error) {
	seen := map[string]bool{}
	var axes []string
	for _, c := range in.Candidates {
		if !seen[c.Axis] {
			seen[c.Axis] = true
			axes = append(axes, c.Axis)
		}
	}
	return advisor.SuggestionOutput{Ranking: axes, Reason: "integration", Confidence: "high", AdvisorID: "itest"}, time.Millisecond, nil
}

// TestSuggestAccept_EndToEnd_WrittenRuleMatchesNextRequest is the #204
// deliverable: boot the host-list proxy from a temp trollbridge.yaml,
// have the suggestion Manager offer a generalization over two specific
// allow entries (GET + POST on the same URL → any-method), accept it,
// and assert that (a) the file now holds the generalized pattern with
// the specific sources pruned, and (b) a DELETE — a method that was NOT
// in the original list — is now allowed by the freshly written rule via
// the allowlist fast path (the matcher recompiled on reload).
func TestSuggestAccept_EndToEnd_WrittenRuleMatchesNextRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin-ok")
	}))
	defer origin.Close()
	originHostPort := strings.TrimPrefix(origin.URL, "http://") // 127.0.0.1:PORT

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	// Two specific allow entries on the same scheme/host/path differing
	// only by method — the input the method-axis detector generalizes.
	yaml := fmt.Sprintf(`mode: default-deny
identities:
  - id: test
    match: {source_ip: 127.0.0.1}
approvals:
  timeout_seconds: 2
  on_timeout: deny
  max_pending: 4
  suggestion:
    enabled: true
    quiet_idle_seconds: 1
    max_candidates: 8
llm:
  enabled: true
  confidence_floor: medium
  on_unavailable: ask_user
lists:
  allow:
    - GET http://%[1]s/data
    - POST http://%[1]s/data
  deny: []
`, originHostPort)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Logging.AuditPath = auditPath

	engine, err := policy.NewEngine(cfg.Mode, nil, policy.KnownModifiers())
	if err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(auditPath, 32, audit.OverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewWithAudit(cfg, engine, logger)
	if err != nil {
		t.Fatal(err)
	}
	// Request-path advisor denies — so anything not short-circuited by
	// the allowlist is denied, making "allowed" unambiguously mean the
	// allowlist rule matched.
	srv.SetAdvisorProvider(&advisor.MockProvider{Output: advisor.Output{Effect: "deny", Confidence: "high"}})
	if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.ServeOnListener(ctx, ln); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(50 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	// Helper: issue a DELETE to the origin through the proxy.
	doDelete := func() (int, string) {
		req, _ := http.NewRequest(http.MethodDelete, origin.URL+"/data", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE through proxy: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	// Before accept: DELETE /data is NOT in the allow list (only GET and
	// POST are), so it must be denied.
	if code, _ := doDelete(); code == http.StatusOK {
		t.Fatalf("DELETE was allowed before the generalization was accepted; want denied")
	}

	// Build the suggestion Manager against the real configwrite + a
	// reload that recompiles the server's matcher from the rewritten file.
	reload := func() {
		fresh, lerr := config.Load(cfgPath)
		if lerr != nil {
			t.Errorf("reload config.Load: %v", lerr)
			return
		}
		if rerr := srv.ReloadListsFromConfig(fresh); rerr != nil {
			t.Errorf("ReloadListsFromConfig: %v", rerr)
		}
	}
	m := suggestion.New(cfgPath, func() *config.Config { return cfg },
		emptyQueue{}, fileLists{path: cfgPath}, rankingAdvisor{}, realWriter{}, reload, srv.opLog)
	// SuggestNow runs detector→rank→offer on demand, bypassing the
	// quiet-idle gate (no clock manipulation needed from this package).
	m.SuggestNow(ctx)
	active := m.Active()
	if active == nil {
		t.Fatal("no active suggestion produced from the GET+POST allow entries")
	}
	pattern := active.Candidate.SuggestedPattern
	if err := m.Accept(ctx, active.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// (a) The file now carries the generalized pattern; the specific
	// source entries are pruned.
	written, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), pattern) {
		t.Errorf("generalized pattern %q not written to config:\n%s", pattern, written)
	}
	if strings.Contains(string(written), "GET http://"+originHostPort+"/data") {
		t.Errorf("specific source entry was not pruned after generalize:\n%s", written)
	}

	// (b) The reload recompiled the matcher: DELETE /data — a method the
	// original list did not contain — is now allowed by the written rule.
	if code, body := doDelete(); code != http.StatusOK || !strings.Contains(body, "origin-ok") {
		t.Fatalf("after accept, DELETE should be allowed by the generalized rule; got status=%d body=%q (pattern=%q)", code, body, pattern)
	}

	// The decision must be attributed to the allowlist (the new rule),
	// not the advisor or a fallthrough.
	cancel()
	<-done
	entries := auditEntries(t, auditPath)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	last := entries[len(entries)-1]
	if last.Decision != "allow" || last.DecisionSource != "allowlist" {
		t.Errorf("last decision = %q/%q, want allow/allowlist (the generalized rule matched)", last.Decision, last.DecisionSource)
	}
}
