// Package suggestion owns the quiet-moment generalization-suggestion
// lifecycle (closes #168). It runs server-side because the daemon is
// the always-on process and the TUI may be detached.
//
// Phases (each emits a structured INFO log entry — partial coverage
// is the recurrent failure shape per #25/#33/#34/#35):
//
//  1. suggestion_detector_ran  — every Tick that crossed the quiet
//                                threshold; carries opportunity_exists,
//                                candidates_found, idle_duration_seconds.
//  2. suggestion_ask_started   — when the advisor is consulted for
//                                ranking. Carries candidates_count,
//                                input_hash, model.
//  3. suggestion_classified    — the advisor returned. Carries
//                                latency_ms, advisor_id, confidence,
//                                ranking, reason.
//  4. suggestion_ask_failed    — advisor returned error. Carries
//                                kind=wire|schema|unknown.
//  5. suggestion_offered       — a row is now active in the pending
//                                area. Carries axis, pattern_shown,
//                                source_entries, list.
//  6. suggestion_accepted      — operator accepted; pattern persisted.
//                                Carries target_list, pattern_added.
//  7. suggestion_declined      — operator declined ALL axes for the
//                                source set; decline row written.
//                                Carries axes_declined.
//  8. decline_filter_suppressed — a candidate matched an existing
//                                decline row at detection time.
//  9. suggestion_superseded    — the lists changed under the active
//                                suggestion (source entries gone).
//
// Per docs/alignment-principles.md §1, the package does NOT let the
// advisor invent patterns: the deterministic detector enumerates the
// candidate set first; the advisor only ranks and narrates within it.
// The mutation gate is the operator's Accept — the advisor has no
// import path to configwrite.
package suggestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/generalize"
	"github.com/dandriscoll/trollbridge/internal/oplog"
)

// QueueProvider is the subset of the approvals queue the suggestion
// lifecycle needs: "is the queue non-empty?" The full queue type
// satisfies this with its existing Pending() method.
type QueueProvider interface {
	Pending() []QueueSnapshot
}

// QueueSnapshot is the suggestion package's view of a held request.
// Mirror of approvals.Snapshot, kept local so the suggestion
// package does not import approvals (which would create a cycle in
// the test wiring).
type QueueSnapshot struct {
	ID string
}

// ListsProvider returns the daemon's current allow/deny lists plus
// the YAML decline section. Re-read every Tick so external edits
// land without restart.
type ListsProvider interface {
	CurrentLists() (allow, deny []string, declined []config.DeclinedSuggestion)
}

// ConfigWriter is the subset of configwrite the package needs.
// Note the AddDeclinedSuggestion shape is "primitive parameters"
// rather than configwrite.DeclinedSuggestion so the interface does
// not pull configwrite types into test seams.
type ConfigWriter interface {
	// Generalize removes the more-specific source entries the
	// generalization replaces and adds the generalized pattern to
	// `list`, atomically (#173).
	Generalize(path, list, pattern string, sources []string) (bool, error)
	AddDeclinedSuggestion(path string, sourceEntries, axesDeclined []string, declinedAt string) (bool, error)
	// AcceptPatternSuggestion appends a YAML rule (built from the
	// PatternMatch payload on a pattern-shaped Candidate) to
	// rulesPath and removes the source entries from listsPath.
	// Closes #203 follow-up: pattern suggestions write a rule, not
	// a hostlist line. Args:
	//   rulesPath: target rule file (typically c.Policy.Include[0])
	//   listsPath: the trollbridge.yaml (m.cfgPath)
	//   list:      "allow" / "deny" — which lists.* the sources live in
	//   ruleID:    deterministic id for the appended rule
	//   pattern:   pattern name, e.g. "azure_arm"
	//   components: constant components map
	//   method:    uppercase HTTP verb, or "" for any
	//   effect:    rule effect; matches list ("allow"/"deny") in v1
	//   sources:   list entries to remove (the rule subsumes them)
	// Returns (ruleChanged, sourcesChanged, error). Caller logs
	// each independently.
	AcceptPatternSuggestion(rulesPath, listsPath, list, ruleID, pattern string, components map[string]string, method, effect string, sources []string) (ruleChanged, sourcesChanged bool, err error)
}

// PatternRecognizer is what suggestion.Manager calls to recognize
// a list-entry URL against the live pattern registry. Satisfied by
// server.Server (which holds the registry). Returns nil when no
// pattern matched; otherwise the pattern name and extracted
// components from the URL.
type PatternRecognizer interface {
	Recognize(host string, port int, scheme, path string) (name string, components map[string]string, ok bool)
}

// AdvisorProvider wraps advisor.Service.Suggest so tests can mock
// it without bringing in the full advisor.Service.
type AdvisorProvider interface {
	Suggest(ctx context.Context, in advisor.SuggestionInput) (advisor.SuggestionOutput, time.Duration, error)
}

// Reloader is invoked after a successful Accept so the daemon
// applies the new list entry immediately. Server.ReloadListsFromConfig
// satisfies this when wrapped.
type Reloader func()

// Manager is the server-side suggestion lifecycle. One per daemon.
type Manager struct {
	cfgPath    string
	rulesPath  string // first include path; "" disables pattern-suggestion accept
	cfg        func() *config.Config // re-read on every Tick so reloads take effect
	queue      QueueProvider
	lists      ListsProvider
	advisor    AdvisorProvider
	writer     ConfigWriter
	reload     Reloader
	recognizer PatternRecognizer // nil disables pattern detection
	opLog      *slog.Logger
	now        func() time.Time
	makeID     func() string
	inbound    atomicTime // updated from any goroutine via NoteInbound
	mu         sync.Mutex
	active     *Suggestion
	// sessionDeclined tracks per-process declines that have not yet
	// produced a YAML decline row. Each entry maps a CanonicalKey
	// to the axes already shown for it this session. When all
	// applicable axes are exhausted, the row is persisted and the
	// entry is removed from this map.
	sessionDeclined map[string]*sessionEntry
}

type sessionEntry struct {
	offered map[string]struct{} // axis names seen-and-declined
}

// Suggestion is the active row offered in the pending area.
type Suggestion struct {
	ID            string
	Candidate     generalize.Candidate
	AllAxes       []generalize.Candidate // siblings for the same CanonicalKey
	OfferedAxes   []string               // axes already shown for this set in this cycle
	Reason        string
	LLMInputHash  string
	OfferedAt     time.Time
	axisRanking   []string
}

// New constructs a Manager. None of the dependencies are optional.
func New(
	cfgPath string,
	cfgGetter func() *config.Config,
	queue QueueProvider,
	lists ListsProvider,
	adv AdvisorProvider,
	writer ConfigWriter,
	reload Reloader,
	opLog *slog.Logger,
) *Manager {
	return &Manager{
		cfgPath:         cfgPath,
		cfg:             cfgGetter,
		queue:           queue,
		lists:           lists,
		advisor:         adv,
		writer:          writer,
		reload:          reload,
		opLog:           opLog,
		now:             time.Now,
		makeID:          newSuggestionID,
		sessionDeclined: map[string]*sessionEntry{},
	}
}

// SetPatternRecognizer wires the live pattern registry so the
// detector can emit pattern-shaped candidates (#203 follow-up).
// nil disables pattern detection without affecting flat detectors.
func (m *Manager) SetPatternRecognizer(r PatternRecognizer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.recognizer = r
	m.mu.Unlock()
}

// SetRulesPath wires the destination rule file pattern-suggestion
// accepts append to. Typically c.Policy.Include[0]. Empty path
// disables pattern-suggestion accept (decline still works); the
// accept path returns a clear error so the operator notices.
func (m *Manager) SetRulesPath(p string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.rulesPath = p
	m.mu.Unlock()
}

// NoteInbound is called from the proxy's main request handler each
// time a request arrives. Cheap and mutex-free.
func (m *Manager) NoteInbound() {
	if m == nil {
		return
	}
	m.inbound.store(m.now())
}

// Active returns the current offered suggestion (nil if none).
// Safe to call from the control-plane HTTP handler concurrently.
func (m *Manager) Active() *Suggestion {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	// Return a copy so callers cannot mutate manager state.
	cp := *m.active
	cp.OfferedAxes = append([]string(nil), m.active.OfferedAxes...)
	cp.AllAxes = append([]generalize.Candidate(nil), m.active.AllAxes...)
	cp.axisRanking = append([]string(nil), m.active.axisRanking...)
	return &cp
}

// Tick is the periodic driver. Call from a daemon ticker (~5 s
// cadence is fine; the quiet predicate gates the expensive work).
func (m *Manager) Tick(ctx context.Context) {
	if m == nil {
		return
	}
	cfg := m.cfg()
	if cfg == nil {
		return
	}
	if !cfg.Approvals.Suggestion.EnabledFor(cfg.LLM) {
		return
	}
	idleSecs := cfg.Approvals.Suggestion.QuietIdleSeconds
	maxCandidates := cfg.Approvals.Suggestion.MaxCandidates

	queueLen := len(m.queue.Pending())
	last := m.inbound.load()
	now := m.now()
	idleDur := now.Sub(last)
	if last.IsZero() {
		idleDur = time.Hour // never received → certainly idle
	}
	quiet := queueLen == 0 && idleDur >= time.Duration(idleSecs)*time.Second

	// If we already have an active suggestion, only revalidate it
	// (supersede if its source entries have disappeared). Don't
	// emit a fresh detector_ran INFO line — quiet would be the
	// common case while a suggestion sits offered.
	if m.activeExists() {
		m.revalidateActive()
		return
	}

	if !quiet {
		// Quiet predicate did not fire. Keep this DEBUG so the
		// every-5s tick doesn't spam INFO during traffic.
		m.opLog.Debug("suggestion detector skipped (not quiet)",
			"event", oplog.EventSuggestionDetectorRan,
			"reason", "not_quiet",
			"queue_len", queueLen,
			"idle_seconds", int(idleDur.Seconds()),
		)
		return
	}

	m.produce(ctx, cfg, maxCandidates, int(idleDur.Seconds()))
}

// SuggestNow runs the detector→rank→offer sequence on demand (#174),
// bypassing the quiet-idle gate that Tick enforces. Any existing
// active suggestion is cleared first so the operator gets a fresh
// scan. No-op when suggestion mode is disabled.
func (m *Manager) SuggestNow(ctx context.Context) {
	if m == nil {
		return
	}
	cfg := m.cfg()
	if cfg == nil || !cfg.Approvals.Suggestion.EnabledFor(cfg.LLM) {
		return
	}
	m.mu.Lock()
	m.active = nil
	m.mu.Unlock()
	m.produce(ctx, cfg, cfg.Approvals.Suggestion.MaxCandidates, 0)
}

// produce is the post-gate core shared by Tick (after the quiet
// predicate) and SuggestNow (on demand): detect candidates, decline-
// filter, group, ask the advisor, and store the top-ranked offer.
// idleSeconds is recorded in the detector log lines (0 for on-demand).
func (m *Manager) produce(ctx context.Context, cfg *config.Config, maxCandidates, idleSeconds int) {
	allow, deny, declined := m.lists.CurrentLists()
	var rec generalize.Recognizer
	if m.recognizer != nil {
		recCB := m.recognizer
		rec = func(host string, port int, scheme, path string) (string, map[string]string, bool) {
			return recCB.Recognize(host, port, scheme, path)
		}
	}
	candidates := generalize.DetectAllWithRecognizer(allow, deny, rec)

	// Decline-filter (YAML) — emit decline_filter_suppressed once
	// per filtered candidate.
	filtered := candidates[:0]
	declineKeys := buildDeclineKeySet(declined)
	for _, c := range candidates {
		key := c.CanonicalKey()
		if _, blocked := declineKeys[key]; blocked {
			m.opLog.Info("decline-filtered candidate",
				"event", oplog.EventSuggestionDeclineFiltered,
				"axis", string(c.Axis),
				"list", c.List,
				"source_count", len(c.SourceEntries),
				"decline_source", "yaml",
			)
			continue
		}
		filtered = append(filtered, c)
	}

	// Decline-filter (in-session) — applies when the same source
	// set has been declined this session but the YAML row hasn't
	// been written yet (because more axes still exist).
	filtered2 := filtered[:0]
	for _, c := range filtered {
		key := c.CanonicalKey()
		entry := m.sessionDeclined[key]
		if entry != nil {
			if _, seen := entry.offered[string(c.Axis)]; seen {
				m.opLog.Info("decline-filtered candidate",
					"event", oplog.EventSuggestionDeclineFiltered,
					"axis", string(c.Axis),
					"list", c.List,
					"source_count", len(c.SourceEntries),
					"decline_source", "session",
				)
				continue
			}
		}
		filtered2 = append(filtered2, c)
	}

	if len(filtered2) == 0 {
		m.opLog.Info("detector found no opportunities",
			"event", oplog.EventSuggestionDetectorRan,
			"opportunity_exists", false,
			"candidates_found", 0,
			"idle_seconds", idleSeconds,
		)
		return
	}

	// Group by CanonicalKey → axis cycle.
	groups := map[string][]generalize.Candidate{}
	for _, c := range filtered2 {
		groups[c.CanonicalKey()] = append(groups[c.CanonicalKey()], c)
	}
	// Pick the highest-priority group. Coverage first: the group whose
	// source set subsumes the most existing list entries wins, so a
	// host-wide generalization is offered before any narrower subset of
	// the same host (#186). Then most axes (more ways to refine the same
	// set), then lexicographically smallest key for determinism. All
	// members of a CanonicalKey group share the same source set, so
	// group coverage is len(SourceEntries) of any member.
	groupCoverage := func(g []generalize.Candidate) int {
		if len(g) == 0 {
			return 0
		}
		return len(g[0].SourceEntries)
	}
	var chosen []generalize.Candidate
	bestKey := ""
	for k, g := range groups {
		better := chosen == nil
		if !better {
			if cg, cc := groupCoverage(g), groupCoverage(chosen); cg != cc {
				better = cg > cc
			} else if len(g) != len(chosen) {
				better = len(g) > len(chosen)
			} else {
				better = k < bestKey
			}
		}
		if better {
			chosen = g
			bestKey = k
		}
	}
	// #190: when the broadest group's source entries cluster
	// heavily under a single 1-segment path prefix, prefer the
	// narrower candidate. The broader-by-default policy (#186)
	// is correct when the operator's list spans the host evenly;
	// it overshoots when the operator has been approving one
	// subset. The narrower candidate is offered when (a) its
	// source set is a strict subset of the chosen, (b) the ratio
	// of subset / chosen entries is >= the configured threshold
	// (default 0.8), and (c) the narrower has the highest
	// qualifying ratio.
	chosen = preferNarrowerOnConcentration(chosen, groups, cfg.Approvals.Suggestion.PathConcentrationThreshold)
	if len(chosen) > maxCandidates {
		chosen = chosen[:maxCandidates]
	}

	m.opLog.Info("detector found opportunity",
		"event", oplog.EventSuggestionDetectorRan,
		"opportunity_exists", true,
		"candidates_found", len(chosen),
		"idle_seconds", idleSeconds,
	)

	// Build advisor input.
	in := advisor.SuggestionInput{
		AllowList: allow,
		DenyList:  deny,
	}
	for _, c := range chosen {
		in.Candidates = append(in.Candidates, advisor.SuggestionCandidate{
			Axis:             string(c.Axis),
			List:             c.List,
			SourceEntries:    c.SourceEntries,
			SuggestedPattern: c.SuggestedPattern,
		})
	}
	inputHash := advisor.SuggestInputHash(in)

	suggestionID := m.makeID()
	cfgLLM := cfg.LLM
	m.opLog.Info("ask started",
		"event", oplog.EventSuggestionAskStarted,
		"suggestion_id", suggestionID,
		"candidates_count", len(chosen),
		"input_hash", inputHash,
		"model", cfgLLM.Model,
	)

	out, latency, err := m.advisor.Suggest(ctx, in)
	if err != nil {
		kind := "unknown"
		switch {
		case errors.Is(err, advisor.ErrAdvisorWire):
			kind = "wire"
		case errors.Is(err, advisor.ErrAdvisorSchema):
			kind = "schema"
		}
		m.opLog.Warn("ask failed",
			"event", oplog.EventSuggestionAskFailed,
			"suggestion_id", suggestionID,
			"kind", kind,
			"latency_ms", latency.Milliseconds(),
			"error", err.Error(),
		)
		return
	}

	m.opLog.Info("classified",
		"event", oplog.EventSuggestionClassified,
		"suggestion_id", suggestionID,
		"latency_ms", latency.Milliseconds(),
		"confidence", out.Confidence,
		"advisor_id", out.AdvisorID,
		"ranking", out.Ranking,
		"reason", out.Reason,
	)

	// Pick the top-ranked candidate.
	top := pickByRanking(chosen, out.Ranking)
	sug := &Suggestion{
		ID:           suggestionID,
		Candidate:    top,
		AllAxes:      chosen,
		OfferedAxes:  []string{string(top.Axis)},
		Reason:       out.Reason,
		LLMInputHash: inputHash,
		OfferedAt:    m.now(),
		axisRanking:  out.Ranking,
	}

	m.mu.Lock()
	m.active = sug
	m.mu.Unlock()

	m.opLog.Info("offered",
		"event", oplog.EventSuggestionOffered,
		"suggestion_id", suggestionID,
		"axis", string(top.Axis),
		"list", top.List,
		"pattern_shown", top.SuggestedPattern,
		"source_count", len(top.SourceEntries),
		"axes_remaining", remainingAxesCount(chosen, sug.OfferedAxes),
	)
}

// preferNarrowerOnConcentration implements #190's concentration-
// aware scorer pass. The detector's broadest candidate (`host/*`)
// is the right offer when the operator's entries are evenly
// distributed across paths under a host; it overshoots when one
// path prefix dominates. Two strategies, tried in order:
//
//  1. Existing-candidate swap. If a narrower group is already in
//     the detector's output (e.g., `host/api/users/*`) and its
//     source set is a strict subset of chosen's with ratio >=
//     threshold, swap to it.
//
//  2. Synthesized 1-segment narrower. The detector emits
//     deepest-common-prefix subsets (`host/api/users/*`,
//     `host/api/orders/*`) and the host-wide rollup (`host/*`)
//     but does not enumerate intermediate-depth prefixes
//     (`host/api/*`). When >= threshold of chosen's entries share
//     a 1-segment path prefix, synthesize that intermediate
//     candidate. The synthesized SourceEntries are exactly the
//     entries under that prefix, so the operator's accept will
//     correctly prune them.
//
// Returns chosen unchanged when no qualifying narrower exists,
// when chosen is empty, when threshold is out of range, or when
// the entries cannot be parsed (defensive fall-through).
func preferNarrowerOnConcentration(chosen []generalize.Candidate, groups map[string][]generalize.Candidate, threshold float64) []generalize.Candidate {
	if len(chosen) == 0 || threshold <= 0 || threshold > 1 {
		return chosen
	}
	chosenSize := len(chosen[0].SourceEntries)
	if chosenSize == 0 {
		return chosen
	}

	// Strategy 1: subset swap.
	chosenSet := map[string]struct{}{}
	for _, s := range chosen[0].SourceEntries {
		chosenSet[s] = struct{}{}
	}
	var best []generalize.Candidate
	bestRatio := 0.0
	for _, g := range groups {
		if len(g) == 0 {
			continue
		}
		size := len(g[0].SourceEntries)
		if size >= chosenSize {
			continue
		}
		subset := true
		for _, s := range g[0].SourceEntries {
			if _, ok := chosenSet[s]; !ok {
				subset = false
				break
			}
		}
		if !subset {
			continue
		}
		ratio := float64(size) / float64(chosenSize)
		if ratio < threshold {
			continue
		}
		if best == nil || ratio > bestRatio || (ratio == bestRatio && len(g) < len(best)) {
			best = g
			bestRatio = ratio
		}
	}
	if best != nil {
		return best
	}

	// Strategy 2: synthesize an intermediate-depth narrower.
	if synth, ok := synthesizeNarrowerFromConcentration(chosen[0], threshold); ok {
		return []generalize.Candidate{synth}
	}
	return chosen
}

// synthesizeNarrowerFromConcentration computes the 1-segment path
// prefix distribution among chosen's source entries. If a single
// prefix accounts for >= threshold of the entries, returns a
// synthesized `METHOD scheme://host/<prefix>/*` candidate with
// SourceEntries set to the matching subset.
//
// Returns ok=false when entries can't be parsed, when no prefix
// dominates, when all entries share a single existing-detector
// shape (no concentration to find), or when chosen's pattern
// isn't a host-wide rollup (intermediate-depth synthesis only
// makes sense as a narrowing of `host/*`).
func synthesizeNarrowerFromConcentration(chosen generalize.Candidate, threshold float64) (generalize.Candidate, bool) {
	// Only narrow host-wide rollups; method/hostname-below-TLD
	// candidates have no path-prefix dimension.
	if !strings.HasSuffix(chosen.SuggestedPattern, "/*") {
		return generalize.Candidate{}, false
	}
	method, schemeHost, ok := splitMethodSchemeHost(chosen.SuggestedPattern)
	if !ok {
		return generalize.Candidate{}, false
	}
	// Cluster the entries by their 1-segment path prefix.
	clusters := map[string][]string{}
	total := 0
	for _, e := range chosen.SourceEntries {
		seg, ok := firstPathSegmentOfEntry(e, method)
		if !ok || seg == "" {
			// An unparseable entry breaks the synthesis assumption
			// (the chosen group should have homogeneous shape).
			return generalize.Candidate{}, false
		}
		clusters[seg] = append(clusters[seg], e)
		total++
	}
	if total == 0 {
		return generalize.Candidate{}, false
	}
	// Find the largest cluster. Deterministic tiebreak: alphabetical
	// segment name (stable across runs even when two segments tie).
	keys := make([]string, 0, len(clusters))
	for k := range clusters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bigSeg := ""
	bigCount := 0
	for _, k := range keys {
		if len(clusters[k]) > bigCount {
			bigSeg = k
			bigCount = len(clusters[k])
		}
	}
	if bigSeg == "" {
		return generalize.Candidate{}, false
	}
	if float64(bigCount)/float64(total) < threshold {
		return generalize.Candidate{}, false
	}
	// Don't synthesize if the cluster IS the chosen (would offer
	// the same pattern). E.g., a single-prefix chosen with all
	// entries already under one segment — the host-wide is the
	// natural offer there.
	if bigCount == total {
		return generalize.Candidate{}, false
	}
	sources := append([]string(nil), clusters[bigSeg]...)
	sort.Strings(sources)
	return generalize.Candidate{
		Axis:             chosen.Axis,
		List:             chosen.List,
		SourceEntries:    sources,
		SuggestedPattern: method + " " + schemeHost + "/" + bigSeg + "/*",
	}, true
}

// splitMethodSchemeHost decomposes a host-wide rollup pattern of
// shape "METHOD scheme://host/*" into (method, "scheme://host",
// ok). Defensive: returns ok=false for any non-matching shape.
func splitMethodSchemeHost(pattern string) (method, schemeHost string, ok bool) {
	parts := strings.SplitN(pattern, " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	method = parts[0]
	rest := parts[1]
	if !strings.HasSuffix(rest, "/*") {
		return "", "", false
	}
	rest = strings.TrimSuffix(rest, "/*")
	// `rest` should now be `scheme://host` (no trailing path).
	if !strings.Contains(rest, "://") {
		return "", "", false
	}
	return method, rest, true
}

// firstPathSegmentOfEntry parses a list entry of shape
// "METHOD scheme://host/path/..." and returns the first non-empty
// path segment. Returns ok=false when the entry doesn't match
// the method or can't be URL-parsed.
func firstPathSegmentOfEntry(entry, wantMethod string) (string, bool) {
	parts := strings.SplitN(entry, " ", 2)
	if len(parts) != 2 || parts[0] != wantMethod {
		return "", false
	}
	u, err := url.Parse(parts[1])
	if err != nil {
		return "", false
	}
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return "", false
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], true
	}
	return p, true
}

// Accept resolves the active suggestion by persisting its pattern
// to the allow or deny list. Returns ErrIDMismatch if id does not
// match the current active suggestion, ErrNoActive if none exists.
func (m *Manager) Accept(ctx context.Context, id string) error {
	m.mu.Lock()
	active := m.active
	if active == nil {
		m.mu.Unlock()
		return ErrNoActive
	}
	if active.ID != id {
		m.mu.Unlock()
		return ErrIDMismatch
	}
	m.active = nil
	delete(m.sessionDeclined, active.Candidate.CanonicalKey())
	m.mu.Unlock()

	pat := active.Candidate.SuggestedPattern
	if active.Candidate.List != "allow" && active.Candidate.List != "deny" {
		return fmt.Errorf("accept: unknown list %q", active.Candidate.List)
	}
	// Pattern-shaped candidate: writes a YAML rule (not a hostlist
	// entry). #203 follow-up — dispatched here so the flat code
	// path below stays unchanged.
	if active.Candidate.PatternMatch != nil {
		return m.acceptPattern(active, pat)
	}
	// Adding the generalized pattern AND removing the more-specific
	// source entries it replaces is the point of generalizing — the
	// list shrinks (#173). One atomic write.
	changed, err := m.writer.Generalize(m.cfgPath, active.Candidate.List, pat, active.Candidate.SourceEntries)
	if err != nil {
		m.opLog.Warn("list persist failure",
			"event", oplog.EventListPersistFailure,
			"pattern", pat,
			"source", "suggestion",
			"error", err.Error(),
		)
		return err
	}
	m.opLog.Info("accepted",
		"event", oplog.EventSuggestionAccepted,
		"suggestion_id", active.ID,
		"target_list", active.Candidate.List,
		"pattern_added", pat,
		"changed", changed,
		"source_count", len(active.Candidate.SourceEntries),
		// Tag the mutation's origin so an operator can tell a
		// daemon-suggested list change from a manual one (#172/#174).
		// Matches the source on the persist-failure line above.
		"source", "suggestion",
	)
	// #172/#174 follow-up: also fire the standard list-mutation
	// event so operators grep'ing `allowlist_added` / `denylist_added`
	// see every list mutation in one place. The `source` field
	// distinguishes suggestion-driven from manual operator entries.
	// Prior to this, suggestion-accepted patterns only appeared in
	// `suggestion_accepted` — operators auditing list mutations had
	// to query two event classes.
	if changed {
		listEvent := oplog.EventAllowlistAdded
		reason := "suggestion_accepted_allow"
		if active.Candidate.List == "deny" {
			listEvent = oplog.EventDenylistAdded
			reason = "suggestion_accepted_deny"
		}
		m.opLog.Info("list persisted",
			"event", listEvent,
			"pattern", pat,
			"source", "suggestion",
			"reason", reason,
			"suggestion_id", active.ID,
		)
	}
	if m.reload != nil {
		m.reload()
	}
	return nil
}

// acceptPattern is the pattern-shaped-candidate accept path
// (#203 follow-up). It writes a YAML rule (built from active's
// PatternMatch) to m.rulesPath and removes the source entries from
// m.cfgPath's lists.<list>. Emits the standard suggestion_accepted
// event plus a follow-up rule_added event so operators grep'ing
// for list mutations also see rule mutations.
func (m *Manager) acceptPattern(active *Suggestion, summary string) error {
	pm := active.Candidate.PatternMatch
	m.mu.Lock()
	rulesPath := m.rulesPath
	m.mu.Unlock()
	if rulesPath == "" {
		err := fmt.Errorf("pattern suggestion accept: no rule file configured under policy.include in trollbridge.yaml; cannot persist a pattern rule")
		m.opLog.Warn("pattern accept failed",
			"event", oplog.EventListPersistFailure,
			"reason", "no_policy_include",
			"suggestion_id", active.ID,
			"pattern", pm.Pattern,
			"error", err.Error())
		return err
	}
	ruleID := patternRuleID(active.Candidate)
	ruleChanged, srcChanged, err := m.writer.AcceptPatternSuggestion(
		rulesPath, m.cfgPath, active.Candidate.List,
		ruleID, pm.Pattern, pm.Components, pm.Method, active.Candidate.List,
		active.Candidate.SourceEntries,
	)
	if err != nil {
		m.opLog.Warn("pattern persist failure",
			"event", oplog.EventListPersistFailure,
			"pattern", pm.Pattern,
			"rule_id", ruleID,
			"source", "suggestion",
			"error", err.Error())
		return err
	}
	m.opLog.Info("accepted",
		"event", oplog.EventSuggestionAccepted,
		"suggestion_id", active.ID,
		"target_list", active.Candidate.List,
		"pattern_added", summary,
		"pattern_name", pm.Pattern,
		"pattern_components", pm.Components,
		"rule_id", ruleID,
		"rule_changed", ruleChanged,
		"sources_changed", srcChanged,
		"source_count", len(active.Candidate.SourceEntries),
		"source", "suggestion",
	)
	if ruleChanged {
		m.opLog.Info("rule added",
			"event", oplog.EventRuleAdded,
			"rule_id", ruleID,
			"pattern", pm.Pattern,
			"effect", active.Candidate.List,
			"source_count", len(active.Candidate.SourceEntries),
			"source", "suggestion",
		)
	}
	if m.reload != nil {
		m.reload()
	}
	return nil
}

// patternRuleID computes a deterministic rule id for a pattern
// candidate. Shape: `suggested-<pattern>-<8hex>` where the hex is
// a sha256 prefix of the CanonicalKey() (sorted source entries).
// Stability: same source set → same id, so a re-accept after the
// first crashes/restarts is idempotent (configwrite skips the
// duplicate id).
func patternRuleID(c generalize.Candidate) string {
	sum := sha256.Sum256([]byte(c.CanonicalKey()))
	pattern := ""
	if c.PatternMatch != nil {
		pattern = c.PatternMatch.Pattern
	}
	return fmt.Sprintf("suggested-%s-%s", pattern, hex.EncodeToString(sum[:4]))
}

// Decline rotates to the next axis if more remain for the same
// source set, else writes the YAML decline row.
func (m *Manager) Decline(ctx context.Context, id string) error {
	m.mu.Lock()
	active := m.active
	if active == nil {
		m.mu.Unlock()
		return ErrNoActive
	}
	if active.ID != id {
		m.mu.Unlock()
		return ErrIDMismatch
	}
	key := active.Candidate.CanonicalKey()
	// Find the next axis for the same set that hasn't been offered.
	offered := map[string]struct{}{}
	for _, a := range active.OfferedAxes {
		offered[a] = struct{}{}
	}
	var next *generalize.Candidate
	for i := range active.AllAxes {
		c := active.AllAxes[i]
		if c.CanonicalKey() != key {
			continue
		}
		if _, seen := offered[string(c.Axis)]; seen {
			continue
		}
		// If the manager ranked, prefer the next axis in ranking
		// order. Otherwise first-applicable wins.
		next = &c
		if active.axisRanking != nil {
			for _, ranked := range active.axisRanking {
				if _, seen := offered[ranked]; seen {
					continue
				}
				for j := range active.AllAxes {
					if string(active.AllAxes[j].Axis) == ranked && active.AllAxes[j].CanonicalKey() == key {
						next = &active.AllAxes[j]
						break
					}
				}
				break
			}
		}
		break
	}

	if next != nil {
		// Rotate.
		entry := m.sessionDeclined[key]
		if entry == nil {
			entry = &sessionEntry{offered: map[string]struct{}{}}
			m.sessionDeclined[key] = entry
		}
		entry.offered[string(active.Candidate.Axis)] = struct{}{}
		active.Candidate = *next
		active.OfferedAxes = append(active.OfferedAxes, string(next.Axis))
		active.OfferedAt = m.now()
		m.active = active
		m.mu.Unlock()

		m.opLog.Info("offered (cycle rotated)",
			"event", oplog.EventSuggestionOffered,
			"suggestion_id", active.ID,
			"axis", string(next.Axis),
			"list", next.List,
			"pattern_shown", next.SuggestedPattern,
			"source_count", len(next.SourceEntries),
			"axes_remaining", remainingAxesCount(active.AllAxes, active.OfferedAxes),
			"reason", "cycle_after_decline",
		)
		return nil
	}

	// No more axes. Write the YAML decline row.
	axesDeclined := append([]string(nil), active.OfferedAxes...)
	m.active = nil
	delete(m.sessionDeclined, key)
	m.mu.Unlock()

	declinedAt := m.now().UTC().Format(time.RFC3339)
	changed, err := m.writer.AddDeclinedSuggestion(m.cfgPath, active.Candidate.SourceEntries, axesDeclined, declinedAt)
	if err != nil {
		m.opLog.Warn("list persist failure",
			"event", oplog.EventListPersistFailure,
			"section", "declined_suggestions",
			"source", "suggestion",
			"error", err.Error(),
		)
		return err
	}
	m.opLog.Info("declined",
		"event", oplog.EventSuggestionDeclined,
		"suggestion_id", active.ID,
		"axes_declined", axesDeclined,
		"source_count", len(active.Candidate.SourceEntries),
		"decline_row_written", changed,
	)
	// Refresh the daemon's in-memory config so the just-written decline
	// row is visible to the next detection cycle. Without this the
	// engine keeps scanning the stale pre-decline list and re-offers the
	// candidate forever (#188) — the decline-path twin of the #183
	// accept-path stale-list re-offer.
	if m.reload != nil {
		m.reload()
	}
	return nil
}

// revalidateActive checks whether the active suggestion's source
// entries still exist in the current allow/deny list. If any have
// disappeared (operator manually removed or wrote a broader pattern
// elsewhere), the active is superseded.
func (m *Manager) revalidateActive() {
	m.mu.Lock()
	active := m.active
	m.mu.Unlock()
	if active == nil {
		return
	}
	allow, deny, _ := m.lists.CurrentLists()
	present := map[string]struct{}{}
	for _, e := range allow {
		present[e] = struct{}{}
	}
	for _, e := range deny {
		present[e] = struct{}{}
	}
	for _, src := range active.Candidate.SourceEntries {
		if _, ok := present[src]; !ok {
			m.mu.Lock()
			if m.active == active {
				m.active = nil
				delete(m.sessionDeclined, active.Candidate.CanonicalKey())
			}
			m.mu.Unlock()
			m.opLog.Info("superseded",
				"event", oplog.EventSuggestionSuperseded,
				"suggestion_id", active.ID,
				"reason", "source_entry_gone",
				"missing_entry", src,
			)
			return
		}
	}
}

func (m *Manager) activeExists() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active != nil
}

// Errors returned by Accept / Decline.
var (
	ErrNoActive   = errors.New("no active suggestion")
	ErrIDMismatch = errors.New("suggestion id mismatch")
)

func buildDeclineKeySet(declined []config.DeclinedSuggestion) map[string]struct{} {
	out := map[string]struct{}{}
	for _, d := range declined {
		// Canonicalize source_entries (sort) so YAML hand-edits that
		// change order still match the detector's canonical form.
		sorted := append([]string(nil), d.SourceEntries...)
		// In-place sort using slices.Sort would be fine, but to
		// avoid importing slices for one call we use sort.
		sortStrings(sorted)
		key := joinNUL(sorted)
		out[key] = struct{}{}
	}
	return out
}

func pickByRanking(candidates []generalize.Candidate, ranking []string) generalize.Candidate {
	if len(candidates) == 0 {
		return generalize.Candidate{}
	}
	for _, axis := range ranking {
		for _, c := range candidates {
			if string(c.Axis) == axis {
				return c
			}
		}
	}
	return candidates[0]
}

func remainingAxesCount(all []generalize.Candidate, offered []string) int {
	seen := map[string]struct{}{}
	for _, a := range offered {
		seen[a] = struct{}{}
	}
	remaining := 0
	for _, c := range all {
		if _, hit := seen[string(c.Axis)]; !hit {
			remaining++
		}
	}
	return remaining
}
