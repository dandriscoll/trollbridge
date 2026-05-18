// Package reloadstatus carries the small value type that surfaces a
// daemon's most-recent hot-reload outcome to the operator. Lives in
// a leaf package so server (which records it), control (which
// JSON-encodes it on /v1/rules), and tui (which renders the badge)
// can all reference the same struct without cycles or duplication.
//
// Closes #129's data-shape requirement: track LastError + LastAt +
// LastSource for the operator-observable badge in the approvals
// pane header. Extended in #165 to per-source state so the badge
// can stack multiple simultaneous failures.
package reloadstatus

import (
	"sort"
	"sync"
	"time"
)

// Status is the operator-observable state of one source's most
// recent hot-reload attempt. A non-empty LastError means the running
// set diverges from the file on disk — the exposure the TUI badge
// surfaces.
//
// Cleared (LastError = "") whenever a subsequent reload of the same
// source succeeds. LastAt advances on every attempt regardless of
// outcome so the operator can see "we tried but it failed at <time>"
// rather than the stale success timestamp.
type Status struct {
	LastError  string    `json:"last_reload_error,omitempty"`
	LastAt     time.Time `json:"last_reload_at,omitempty"`
	LastSource string    `json:"last_reload_source,omitempty"`
	// FailingSources lists every source whose most-recent reload
	// errored (#165). Populated by Get() so TUI / /v1/rules
	// consumers can render multiple simultaneous failures without
	// querying the Tracker separately. Empty / omitted when no
	// source is failing.
	FailingSources []string `json:"failing_sources,omitempty"`
}

// Tracker holds per-source reload state plus a summary view. The
// per-source map lets the operator-facing surfaces (TUI badge,
// /v1/rules) report multiple simultaneous failures (#165) — a
// config-fail followed by a rules-fail no longer masks the config-
// fail through overwrite.
type Tracker struct {
	mu       sync.Mutex
	sources  map[string]Status // keyed by source name (config / rules / lists)
	mostRecent Status          // last-write-wins view for legacy consumers
}

// Record writes the outcome of a reload attempt. source is one of
// "config" | "rules" | "lists"; err is nil on success.
func (t *Tracker) Record(source string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sources == nil {
		t.sources = make(map[string]Status, 3)
	}
	now := time.Now().UTC()
	s := Status{LastAt: now, LastSource: source}
	if err != nil {
		s.LastError = err.Error()
	}
	t.sources[source] = s
	t.mostRecent = s
}

// Get returns the most-recently-recorded outcome regardless of
// source, with FailingSources populated for multi-source
// rendering (#165). The legacy LastError / LastAt / LastSource
// fields stay aligned with the most-recent attempt so pre-#165
// consumers see no behavior change. Safe for concurrent use; the
// returned value's FailingSources slice is freshly allocated and
// not aliased.
func (t *Tracker) Get() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.mostRecent
	var failing []string
	for name, src := range t.sources {
		if src.LastError != "" {
			failing = append(failing, name)
		}
	}
	if len(failing) > 0 {
		sort.Strings(failing)
		s.FailingSources = failing
	}
	return s
}

// Sources returns a snapshot of every source's most-recent
// reload outcome, keyed by source name. The returned map is
// owned by the caller (a copy of the internal state).
func (t *Tracker) Sources() map[string]Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sources) == 0 {
		return nil
	}
	out := make(map[string]Status, len(t.sources))
	for k, v := range t.sources {
		out[k] = v
	}
	return out
}

// FailingSources returns the names of sources whose most-recent
// reload attempt errored, sorted alphabetically for stable output.
// The TUI badge renders one badge per name; /v1/rules can expose
// the list in its JSON payload (#165). Returns nil when every
// source is clean (or no reloads have been attempted).
func (t *Tracker) FailingSources() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for name, s := range t.sources {
		if s.LastError != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
