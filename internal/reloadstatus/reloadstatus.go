// Package reloadstatus carries the small value type that surfaces a
// daemon's most-recent hot-reload outcome to the operator. Lives in
// a leaf package so server (which records it), control (which
// JSON-encodes it on /v1/rules), and tui (which renders the badge)
// can all reference the same struct without cycles or duplication.
//
// Closes #129's data-shape requirement: track LastError + LastAt +
// LastSource for the operator-observable badge in the approvals
// pane header.
package reloadstatus

import (
	"sync"
	"time"
)

// Status is the operator-observable state of the most recent
// hot-reload attempt across config / rules / lists. A non-empty
// LastError means the running set diverges from the file on disk —
// the exposure the TUI badge surfaces.
//
// Cleared (LastError = "") whenever a subsequent reload succeeds.
// LastAt advances on every attempt regardless of outcome so the
// operator can see "we tried but it failed at <time>" rather than
// the stale success timestamp.
type Status struct {
	LastError  string    `json:"last_reload_error,omitempty"`
	LastAt     time.Time `json:"last_reload_at,omitempty"`
	LastSource string    `json:"last_reload_source,omitempty"`
}

// Tracker is the thread-safe shadow state behind Status. Server
// embeds one; the daemon calls Record after every reload attempt
// and Get returns a value snapshot for the control plane.
type Tracker struct {
	mu     sync.Mutex
	status Status
}

// Record writes the outcome of a reload attempt. source is one of
// "config" | "rules" | "lists"; err is nil on success.
func (t *Tracker) Record(source string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.LastAt = time.Now().UTC()
	t.status.LastSource = source
	if err != nil {
		t.status.LastError = err.Error()
	} else {
		t.status.LastError = ""
	}
}

// Get returns a snapshot of the current reload state. Safe for
// concurrent use; the returned value is not aliased.
func (t *Tracker) Get() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}
