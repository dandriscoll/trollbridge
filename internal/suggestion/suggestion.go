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
	"errors"
	"fmt"
	"log/slog"
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
	AddAllow(path, pattern string) (bool, error)
	AddDeny(path, pattern string) (bool, error)
	AddDeclinedSuggestion(path string, sourceEntries, axesDeclined []string, declinedAt string) (bool, error)
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
	cfgPath  string
	cfg      func() *config.Config // re-read on every Tick so reloads take effect
	queue    QueueProvider
	lists    ListsProvider
	advisor  AdvisorProvider
	writer   ConfigWriter
	reload   Reloader
	opLog    *slog.Logger
	now      func() time.Time
	makeID   func() string
	inbound  atomicTime // updated from any goroutine via NoteInbound
	mu       sync.Mutex
	active   *Suggestion
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

	allow, deny, declined := m.lists.CurrentLists()
	candidates := generalize.DetectAll(allow, deny)

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
			"idle_seconds", int(idleDur.Seconds()),
		)
		return
	}

	// Group by CanonicalKey → axis cycle.
	groups := map[string][]generalize.Candidate{}
	for _, c := range filtered2 {
		groups[c.CanonicalKey()] = append(groups[c.CanonicalKey()], c)
	}
	// Pick the highest-priority group: most axes first, then
	// lexicographically smallest key for determinism.
	var chosen []generalize.Candidate
	bestKey := ""
	for k, g := range groups {
		if chosen == nil || len(g) > len(chosen) || (len(g) == len(chosen) && k < bestKey) {
			chosen = g
			bestKey = k
		}
	}
	if len(chosen) > maxCandidates {
		chosen = chosen[:maxCandidates]
	}

	m.opLog.Info("detector found opportunity",
		"event", oplog.EventSuggestionDetectorRan,
		"opportunity_exists", true,
		"candidates_found", len(chosen),
		"idle_seconds", int(idleDur.Seconds()),
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
	var changed bool
	var err error
	switch active.Candidate.List {
	case "allow":
		changed, err = m.writer.AddAllow(m.cfgPath, pat)
	case "deny":
		changed, err = m.writer.AddDeny(m.cfgPath, pat)
	default:
		return fmt.Errorf("accept: unknown list %q", active.Candidate.List)
	}
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
	)
	if m.reload != nil {
		m.reload()
	}
	return nil
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
