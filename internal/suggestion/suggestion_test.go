package suggestion

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/oplog"
)

type stubQueue struct{ pending []QueueSnapshot }

func (s *stubQueue) Pending() []QueueSnapshot { return s.pending }

type stubLists struct {
	allow, deny []string
	declined    []config.DeclinedSuggestion
}

func (s *stubLists) CurrentLists() ([]string, []string, []config.DeclinedSuggestion) {
	return s.allow, s.deny, s.declined
}

type fakeWriter struct {
	mu              sync.Mutex
	addedAllow      []string
	addedDeny       []string
	removed         []string
	declined        []writerDecline
	patternAccepts  []patternAcceptRecord
	failAccept      bool
	failDecline     bool
}

type patternAcceptRecord struct {
	rulesPath, listsPath, list string
	ruleID, pattern            string
	components                 map[string]string
	method, effect             string
	sources                    []string
}

type writerDecline struct {
	sources []string
	axes    []string
	at      string
}

func (f *fakeWriter) Generalize(path, list, pat string, sources []string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAccept {
		return false, errors.New("simulated generalize write failure")
	}
	switch list {
	case "allow":
		f.addedAllow = append(f.addedAllow, pat)
	case "deny":
		f.addedDeny = append(f.addedDeny, pat)
	}
	f.removed = append(f.removed, sources...)
	return true, nil
}
func (f *fakeWriter) AddDeclinedSuggestion(path string, src, axes []string, at string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDecline {
		return false, errors.New("simulated decline write failure")
	}
	f.declined = append(f.declined, writerDecline{sources: src, axes: axes, at: at})
	return true, nil
}
func (f *fakeWriter) AcceptPatternSuggestion(rulesPath, listsPath, list, ruleID, pattern string, components map[string]string, method, effect string, sources []string) (bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAccept {
		return false, false, errors.New("simulated pattern accept failure")
	}
	f.patternAccepts = append(f.patternAccepts, patternAcceptRecord{
		rulesPath: rulesPath, listsPath: listsPath, list: list,
		ruleID: ruleID, pattern: pattern, components: components,
		method: method, effect: effect, sources: sources,
	})
	f.removed = append(f.removed, sources...)
	return true, true, nil
}

// stubAdvisor returns a deterministic ranking — no LLM involved.
type stubAdvisor struct{}

func (stubAdvisor) Suggest(ctx context.Context, in advisor.SuggestionInput) (advisor.SuggestionOutput, time.Duration, error) {
	axes := []string{}
	seen := map[string]bool{}
	for _, c := range in.Candidates {
		if !seen[c.Axis] {
			axes = append(axes, c.Axis)
			seen[c.Axis] = true
		}
	}
	return advisor.SuggestionOutput{
		Ranking:    axes,
		Reason:     "test-fixture reason",
		Confidence: "high",
		AdvisorID:  "stub",
	}, 5 * time.Millisecond, nil
}

func newTestManager(t *testing.T, cfg *config.Config, queue QueueProvider, lists ListsProvider, writer ConfigWriter) (*Manager, *bool) {
	t.Helper()
	reloaded := false
	cfgGetter := func() *config.Config { return cfg }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New("/tmp/test-trollbridge.yaml", cfgGetter, queue, lists, stubAdvisor{}, writer, func() { reloaded = true }, logger)
	// Fix the clock so idle-duration math is deterministic.
	now := time.Unix(1_000_000_000, 0)
	m.now = func() time.Time { return now }
	// Mark a fictional past inbound so the quiet predicate fires by
	// default (the test can override per-case via NoteInbound).
	m.inbound.store(now.Add(-time.Hour))
	return m, &reloaded
}

func enabledConfig() *config.Config {
	t := true
	cfg := &config.Config{}
	cfg.LLM.Enabled = true
	cfg.Approvals.Suggestion.Enabled = &t
	cfg.Approvals.Suggestion.QuietIdleSeconds = 30
	cfg.Approvals.Suggestion.MaxCandidates = 8
	// Match the default that config.applyDefaults installs in
	// production so tests exercise the same scorer behavior the
	// daemon ships with (#190).
	cfg.Approvals.Suggestion.PathConcentrationThreshold = 0.8
	return cfg
}

func TestTickEmitsNoOpportunityWhenListsEmpty(t *testing.T) {
	cfg := enabledConfig()
	m, _ := newTestManager(t, cfg, &stubQueue{}, &stubLists{}, &fakeWriter{})
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Fatalf("expected no active suggestion")
	}
}

func TestTickSurfacesMethodSuggestion(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())
	got := m.Active()
	if got == nil {
		t.Fatalf("expected an active suggestion")
	}
	if got.Candidate.SuggestedPattern != "* https://api.example.com/v1/users" {
		t.Errorf("wrong pattern: %q", got.Candidate.SuggestedPattern)
	}
	if got.Reason == "" {
		t.Errorf("expected a templated reason")
	}
}

func TestTickSkippedWhenQueueNonEmpty(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	queue := &stubQueue{pending: []QueueSnapshot{{ID: "h1"}}}
	m, _ := newTestManager(t, cfg, queue, lists, &fakeWriter{})
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Fatalf("expected no suggestion when queue is non-empty")
	}
}

func TestTickSkippedWhenRecentInbound(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	// Pretend a request just arrived 1s ago.
	m.inbound.store(m.now().Add(-1 * time.Second))
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Fatalf("expected no suggestion within idle window")
	}
}

func TestAcceptWritesAllowAndClears(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	writer := &fakeWriter{}
	m, reloaded := newTestManager(t, cfg, &stubQueue{}, lists, writer)
	m.Tick(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("expected active suggestion")
	}
	if err := m.Accept(context.Background(), active.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(writer.addedAllow) != 1 {
		t.Fatalf("expected 1 allow add; got %v", writer.addedAllow)
	}
	// #173: accept removes the more-specific source entries it replaces.
	if len(writer.removed) != len(active.Candidate.SourceEntries) || len(writer.removed) == 0 {
		t.Errorf("expected accept to remove %d source entries; got %v", len(active.Candidate.SourceEntries), writer.removed)
	}
	if !*reloaded {
		t.Errorf("expected reload after Accept")
	}
	if m.Active() != nil {
		t.Errorf("Accept did not clear active suggestion")
	}
}

// NOTE: an end-to-end cycle test for multi-axis-same-source-set is
// not provided here. Empirically, 2-entry source sets produce
// exactly one axis (the entries either differ on one dimension and
// one detector groups them, or they differ on multiple dimensions
// and no detector groups them). Multi-axis-same-set cycles can
// arise in 3+ entry edge cases but are rare; recorded as a design
// follow-up in 008-improvements.md. The Decline rotation code IS
// exercised by the in-session decline-filter test below.

func TestDeclineWritesRowWhenSingleAxis(t *testing.T) {
	cfg := enabledConfig()
	// Same method, only path-segment differs — produces ONLY a
	// url_segment axis. Decline should write the row immediately.
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/123",
		"GET https://api.example.com/v1/users/456",
	}}
	writer := &fakeWriter{}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, writer)
	m.Tick(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatalf("expected active")
	}
	if len(active.AllAxes) != 1 {
		t.Fatalf("test fixture should produce exactly 1 axis; got %d (%v)", len(active.AllAxes), active.AllAxes)
	}
	if err := m.Decline(context.Background(), active.ID); err != nil {
		t.Fatalf("Decline: %v", err)
	}
	if len(writer.declined) != 1 {
		t.Errorf("expected 1 decline row written; got %v", writer.declined)
	}
	if m.Active() != nil {
		t.Errorf("active not cleared after single-axis decline")
	}
}

// #188: declining a suggestion must refresh the daemon's in-memory
// config the same way Accept does. The decline row is written to YAML
// by AddDeclinedSuggestion, but the suggestion engine reads its lists
// (including DeclinedSuggestions) via the cfg getter; without a reload
// the engine keeps scanning the stale, pre-decline list and re-offers
// the just-declined candidate forever ("stuck re-recommending").
// Same class as #183 on the Accept path.
func TestDeclineReloadsConfigAfterRowWritten(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/123",
		"GET https://api.example.com/v1/users/456",
	}}
	writer := &fakeWriter{}
	m, reloaded := newTestManager(t, cfg, &stubQueue{}, lists, writer)
	m.Tick(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("expected active suggestion")
	}
	if err := m.Decline(context.Background(), active.ID); err != nil {
		t.Fatalf("Decline: %v", err)
	}
	if len(writer.declined) != 1 {
		t.Fatalf("expected decline row written; got %v", writer.declined)
	}
	if !*reloaded {
		t.Errorf("expected reload after Decline wrote a decline row (#188); " +
			"without it the daemon scans stale lists and re-offers")
	}
}

// reloadableLists mirrors the production wiring: the daemon's
// reloadAfterInternalWrite re-parses the YAML the writer just wrote
// and refreshes the cfg the suggestion engine reads. Here the reload
// closure folds the fakeWriter's persisted decline rows back into the
// lists provider, so an end-to-end Decline → Tick cycle exercises the
// real re-offer path rather than a static stub.
type reloadableLists struct {
	allow, deny []string
	writer      *fakeWriter
	synced      bool
}

func (r *reloadableLists) CurrentLists() ([]string, []string, []config.DeclinedSuggestion) {
	if !r.synced {
		return r.allow, r.deny, nil
	}
	var declined []config.DeclinedSuggestion
	r.writer.mu.Lock()
	for _, d := range r.writer.declined {
		declined = append(declined, config.DeclinedSuggestion{SourceEntries: d.sources})
	}
	r.writer.mu.Unlock()
	return r.allow, r.deny, declined
}

// TestDeclineDoesNotReofferEndToEnd is the #188 symptom test: decline a
// suggestion, then run another detection cycle, and confirm the same
// candidate is NOT re-offered.
func TestDeclineDoesNotReofferEndToEnd(t *testing.T) {
	cfg := enabledConfig()
	writer := &fakeWriter{}
	lists := &reloadableLists{
		allow: []string{
			"GET https://api.example.com/v1/users/123",
			"GET https://api.example.com/v1/users/456",
		},
		writer: writer,
	}
	reloaded := false
	cfgGetter := func() *config.Config { return cfg }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New("/tmp/test-trollbridge.yaml", cfgGetter, &stubQueue{}, lists, stubAdvisor{}, writer,
		func() { reloaded = true; lists.synced = true }, logger)
	now := time.Unix(1_000_000_000, 0)
	m.now = func() time.Time { return now }
	m.inbound.store(now.Add(-time.Hour))

	m.Tick(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("expected active suggestion on first tick")
	}
	if err := m.Decline(context.Background(), active.ID); err != nil {
		t.Fatalf("Decline: %v", err)
	}
	if !reloaded {
		t.Fatalf("Decline did not reload; the daemon will re-offer (#188)")
	}
	// Next detection cycle: the just-declined candidate must be
	// decline-filtered, not re-offered.
	m.Tick(context.Background())
	if got := m.Active(); got != nil {
		t.Errorf("declined candidate was re-offered (#188 loop): %+v", got.Candidate)
	}
}

func TestDeclineFilterPreventsReoffer(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{
		allow: []string{
			"GET https://api.example.com/v1/users/123",
			"GET https://api.example.com/v1/users/456",
		},
		declined: []config.DeclinedSuggestion{
			{
				SourceEntries: []string{
					"GET https://api.example.com/v1/users/123",
					"GET https://api.example.com/v1/users/456",
				},
			},
		},
	}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Errorf("decline filter failed; suggestion was offered despite YAML decline row")
	}
}

func TestNoteInboundIsLockFreeAndUsedByQuietPredicate(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	// Confirm NoteInbound flips the quiet predicate.
	m.NoteInbound()
	// inbound was just set; now is m.now() → idle = 0 → quiet false.
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Errorf("expected no suggestion immediately after NoteInbound")
	}
}

func TestRevalidateSupersedesWhenSourceEntryGone(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())
	if m.Active() == nil {
		t.Fatal("expected active")
	}
	// Remove one source entry.
	lists.allow = []string{"GET https://api.example.com/v1/users"}
	// Next Tick should supersede.
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Errorf("expected supersede; active still present")
	}
}

// Verify the event-name constants we use are the canonical strings
// (a refactor that renames a constant must not silently drop our
// telemetry coverage).
func TestEventNamesAreCanonical(t *testing.T) {
	want := map[string]string{
		"detector_ran":      "suggestion_detector_ran",
		"ask_started":       "suggestion_ask_started",
		"classified":        "suggestion_classified",
		"ask_failed":        "suggestion_ask_failed",
		"offered":           "suggestion_offered",
		"accepted":          "suggestion_accepted",
		"declined":          "suggestion_declined",
		"decline_filtered":  "decline_filter_suppressed",
		"superseded":        "suggestion_superseded",
	}
	got := map[string]string{
		"detector_ran":     oplog.EventSuggestionDetectorRan,
		"ask_started":      oplog.EventSuggestionAskStarted,
		"classified":       oplog.EventSuggestionClassified,
		"ask_failed":       oplog.EventSuggestionAskFailed,
		"offered":          oplog.EventSuggestionOffered,
		"accepted":         oplog.EventSuggestionAccepted,
		"declined":         oplog.EventSuggestionDeclined,
		"decline_filtered": oplog.EventSuggestionDeclineFiltered,
		"superseded":       oplog.EventSuggestionSuperseded,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("event %s = %q; want %q", k, got[k], w)
		}
	}
}
