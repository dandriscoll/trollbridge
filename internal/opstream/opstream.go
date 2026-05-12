// Package opstream is the in-memory rolling record of recent
// operations (proxy requests) the operator UI displays. It is not
// telemetry — the audit log and the slog event stream remain the
// authoritative records — but a bounded, structured view the TUI can
// read at every refresh tick to show "what is the proxy doing right
// now" with stable per-row identity (closes #52).
//
// The ring is keyed by request_id so that an operation transitioning
// evaluating → pending → resolved updates the same row in the TUI
// instead of producing a new line at each transition.
package opstream

import (
	"sync"
	"time"
)

// DefaultCap is the default ring capacity. Picked to comfortably
// exceed Approvals.MaxPending's default (100) only in worst-case
// burst; the operator UI does not need a long history — the audit
// log carries that.
const DefaultCap = 50

// Op-status string constants. Stringified HTTP status codes
// ("200", "403", "502") appear in Op.Status when an upstream
// response status was sent. The non-numeric states cover the
// lifecycle before / outside of a normal HTTP response (closes #57)
// AND the trollbridge-internal wire codes (470 / 471) which are not
// real HTTP statuses and must not be displayed as numeric codes
// (closes #71).
const (
	// StatusChecking — the LLM advisor is evaluating, or the policy
	// engine has not yet decided. Pre-decision and brief.
	StatusChecking = "checking"
	// StatusPending — held for human approval (TUI / attach operator).
	StatusPending = "pending"
	// StatusRunning — decision is allow, response not yet complete.
	// writeAudit overwrites with the upstream HTTP code on response.
	StatusRunning = "running"
	// StatusError — pre-HTTP error (no status sent), e.g., upstream
	// dial failure, body-read failure, hijack failure.
	StatusError = "error"
	// StatusDenied — the proxy denied the request. Surfaces in place
	// of the trollbridge-internal 470 wire code; the consumer's wire
	// response still carries 470 but the operator-facing display uses
	// a name, not a number (closes #71).
	StatusDenied = "denied"
	// StatusSignaled — the proxy emitted a 471 pending-signal to the
	// consumer (approvals.signal_after_seconds fired); the hold
	// remains in the queue. Surfaces in place of "471" for the same
	// reason as StatusDenied: 471 is a trollbridge-internal wire code,
	// not a real HTTP status.
	StatusSignaled = "signaled"
	// StatusTLSFailed — the inner TLS handshake on an intercepted
	// CONNECT failed before any HTTP request could be parsed. The
	// matching audit entry carries a tls_error_category and the
	// recorded ClientHello details. Distinct from StatusError so
	// the operator UI can render handshake failures as a class.
	StatusTLSFailed = "tls_failed"
)

// Op is one operation's view-state. JSON tags exist because /v1/ops
// emits this directly.
type Op struct {
	RequestID         string    `json:"request_id"`
	Method            string    `json:"method"`
	URL               string    `json:"url"`
	Status            string    `json:"status"`
	HoldID            string    `json:"hold_id,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LatencyMS         int64     `json:"latency_ms,omitempty"`
	ResponseSizeBytes int64     `json:"response_size_bytes,omitempty"`
}

// Ring is a bounded, request-id-keyed buffer of recent operations.
// Safe for concurrent use.
type Ring struct {
	mu    sync.Mutex
	cap   int
	items map[string]*Op
	order []string // request_id, oldest at front; eviction pops from front
	now   func() time.Time
}

// New returns a Ring with the given capacity. cap <= 0 falls back to
// DefaultCap.
func New(cap int) *Ring {
	if cap <= 0 {
		cap = DefaultCap
	}
	return &Ring{
		cap:   cap,
		items: make(map[string]*Op, cap),
		order: make([]string, 0, cap),
		now:   time.Now,
	}
}

// Begin records a new operation in the checking state. If an entry
// for requestID already exists (re-entry — should not happen in
// practice since request_ids are UUIDs) the existing entry is
// preserved and only the timestamp is bumped.
func (r *Ring) Begin(requestID, method, url string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if op, ok := r.items[requestID]; ok {
		op.UpdatedAt = now
		return
	}
	if len(r.order) >= r.cap {
		// Evict oldest.
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.items, oldest)
	}
	op := &Op{
		RequestID: requestID,
		Method:    method,
		URL:       url,
		Status:    StatusChecking,
		StartedAt: now,
		UpdatedAt: now,
	}
	r.items[requestID] = op
	r.order = append(r.order, requestID)
}

// HoldPending marks an in-flight operation as awaiting human
// approval. holdID is the approvals.Queue id the operator will act
// on. Silent no-op if the operation is unknown — the operation may
// have been evicted under burst pressure.
func (r *Ring) HoldPending(requestID, holdID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.items[requestID]
	if !ok {
		return
	}
	op.Status = StatusPending
	op.HoldID = holdID
	op.UpdatedAt = r.now()
}

// Rebind relabels an existing entry under a new identity. Used when
// an intercepted CONNECT's inner TLS flow becomes available: the
// outer `CONNECT host:443` placeholder row gets replaced by the inner
// request's method+URL so the operator sees the real operation, not
// the tunnel. Status resets to checking; the next writeAudit/
// HoldPending call on newID transitions it from there. Returns false
// when oldID has been evicted, so the caller falls back to Begin.
// Closes #75.
func (r *Ring) Rebind(oldID, newID, method, url string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.items[oldID]
	if !ok {
		return false
	}
	if oldID != newID {
		if _, clash := r.items[newID]; clash {
			return false
		}
		delete(r.items, oldID)
		for i, id := range r.order {
			if id == oldID {
				r.order[i] = newID
				break
			}
		}
		op.RequestID = newID
		r.items[newID] = op
	}
	op.Method = method
	op.URL = url
	op.Status = StatusChecking
	op.HoldID = ""
	op.UpdatedAt = r.now()
	return true
}

// Resolve moves an operation to a terminal status. status is a free-
// form string — typically one of the Status constants or a
// stringified HTTP status code. latencyMS and sizeBytes carry the
// most-recent-request stats the info pane renders (closes #90); pass
// 0 when no terminal data is available (e.g., for the transient
// "running" transition before the response completes). Silent no-op
// if the operation is unknown.
func (r *Ring) Resolve(requestID, status string, latencyMS int64, sizeBytes int64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.items[requestID]
	if !ok {
		return
	}
	op.Status = status
	op.HoldID = ""
	op.UpdatedAt = r.now()
	if latencyMS > 0 {
		op.LatencyMS = latencyMS
	}
	if sizeBytes > 0 {
		op.ResponseSizeBytes = sizeBytes
	}
}

// Snapshot returns a copy of the current operations, newest-updated
// first. Safe to mutate; the returned slice does not alias ring
// state.
func (r *Ring) Snapshot() []Op {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Op, 0, len(r.order))
	for _, id := range r.order {
		if op, ok := r.items[id]; ok {
			out = append(out, *op)
		}
	}
	// Sort newest-first by UpdatedAt; insertion order is the
	// tiebreaker through the loop above (older items first), so
	// reverse-iteration combined with a stable secondary key would
	// produce the same result. A single explicit sort keeps the
	// invariant audit-able.
	sortByUpdatedDesc(out)
	return out
}

func sortByUpdatedDesc(ops []Op) {
	// Simple insertion sort — n is bounded by ring cap (default 50).
	for i := 1; i < len(ops); i++ {
		j := i
		for j > 0 && ops[j].UpdatedAt.After(ops[j-1].UpdatedAt) {
			ops[j], ops[j-1] = ops[j-1], ops[j]
			j--
		}
	}
}
