// Package approvals implements the held-request queue. See
// DESIGN.md §8.5.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/google/uuid"
)

// Logger is the slog subset the queue uses for hold-lifecycle Info
// events. *slog.Logger satisfies it. Defined locally so this
// package does not import log/slog.
type Logger interface {
	Info(msg string, args ...any)
}

// Hold is a request waiting for operator action.
type Hold struct {
	ID        string
	Request   *types.RequestEvent
	Decision  types.Decision    // the engine's ask_user decision; carries reason
	CreatedAt time.Time
	resolveCh chan types.Decision
}

// Snapshot returns a JSON-friendly description of the hold (used by
// CLI/control API).
type Snapshot struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	IdentityID string    `json:"identity_id"`
	Method     string    `json:"method"`
	Scheme     string    `json:"scheme"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Path       string    `json:"path"`
	Reason     string    `json:"reason"`
	RuleID     string    `json:"rule_id"`
}

// Queue is a bounded in-memory map of pending holds.
type Queue struct {
	maxPending int
	timeout    time.Duration
	onTimeout  string // "deny" | "allow"

	mu    sync.Mutex
	items map[string]*Hold

	// opLog, when set, receives Info events on hold lifecycle
	// transitions (approve, deny, timeout). nil-safe.
	opLog Logger
}

// SetLogger wires an optional logger that the queue uses to emit
// hold-lifecycle Info events.
func (q *Queue) SetLogger(l Logger) { q.opLog = l }

// New constructs a Queue.
func New(maxPending int, timeout time.Duration, onTimeout string) *Queue {
	if maxPending <= 0 {
		maxPending = 100
	}
	if onTimeout == "" {
		onTimeout = "deny"
	}
	return &Queue{
		maxPending: maxPending,
		timeout:    timeout,
		onTimeout:  onTimeout,
		items:      map[string]*Hold{},
	}
}

// ErrFull is returned when the queue is at capacity.
var ErrFull = errors.New("approval queue full")

// Enqueue creates a new Hold and stores it. Returns the hold ID and
// a channel that resolves with the operator's decision (or a
// timeout/shutdown deny).
func (q *Queue) Enqueue(req *types.RequestEvent, baseDecision types.Decision) (string, <-chan types.Decision, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.maxPending {
		return "", nil, ErrFull
	}
	id := "hold-" + uuid.NewString()
	h := &Hold{
		ID:        id,
		Request:   req,
		Decision:  baseDecision,
		CreatedAt: time.Now().UTC(),
		resolveCh: make(chan types.Decision, 1),
	}
	q.items[id] = h
	return id, h.resolveCh, nil
}

// Wait blocks on the hold until resolution or the configured
// timeout elapses. The returned Decision will reflect the final
// outcome including timeout-deny / timeout-allow / shutdown-deny.
func (q *Queue) Wait(ctx context.Context, id string, ch <-chan types.Decision) types.Decision {
	timer := time.NewTimer(q.timeout)
	defer timer.Stop()
	select {
	case d := <-ch:
		q.remove(id)
		return d
	case <-timer.C:
		// Snapshot the hold's identifying fields before remove() —
		// the post-emit log carries them but the map entry is gone.
		var snap *Hold
		q.mu.Lock()
		if h, ok := q.items[id]; ok {
			snap = h
		}
		q.mu.Unlock()
		q.remove(id)
		eff := types.EffectAskUserTimedOut
		switch q.onTimeout {
		case "allow":
			eff = types.EffectAskUserResolvedAllow
		default:
			// timeout deny shows up explicitly so audit can
			// distinguish from a normal deny.
			eff = types.EffectAskUserTimedOut
		}
		if q.opLog != nil && snap != nil {
			q.opLog.Info("hold timed out",
				"event", oplog.EventHoldTimedOut,
				"hold_id", snap.ID,
				"request_id", snap.Request.ID,
				"identity", snap.Request.IdentityID,
				"method", snap.Request.Method,
				"scheme", snap.Request.Scheme,
				"host", snap.Request.Host,
				"port", snap.Request.Port,
				"on_timeout", q.onTimeout,
				"timeout_seconds", int(q.timeout.Seconds()))
		}
		return types.Decision{
			Effect: eff,
			Source: types.SourceApprovalTimeout,
			Reason: fmt.Sprintf("approval timeout after %s", q.timeout),
		}
	case <-ctx.Done():
		q.remove(id)
		return types.Decision{
			Effect: types.EffectAskUserResolvedDeny,
			Source: types.SourceApprovalTimeout,
			Reason: "trollbridge shutdown; approvals denied",
		}
	}
}

// Approve resolves the hold with an allow decision. Returns
// false if the hold was not found.
func (q *Queue) Approve(id, scope string) bool {
	q.mu.Lock()
	h, ok := q.items[id]
	q.mu.Unlock()
	if !ok {
		return false
	}
	if scope == "" {
		scope = "once"
	}
	h.resolveCh <- types.Decision{
		Effect:    types.EffectAskUserResolvedAllow,
		Source:    types.SourceApprovalQueue,
		RuleID:    h.Decision.RuleID,
		Reason:    "operator approved",
		Scope:     scope,
		Modifiers: append([]string(nil), h.Decision.Modifiers...),
	}
	if q.opLog != nil {
		q.opLog.Info("hold approved by operator",
			"event", oplog.EventHoldApproved,
			"hold_id", h.ID,
			"request_id", h.Request.ID,
			"identity", h.Request.IdentityID,
			"method", h.Request.Method,
			"scheme", h.Request.Scheme,
			"host", h.Request.Host,
			"port", h.Request.Port,
			"scope", scope)
	}
	return true
}

// Deny resolves the hold with a deny decision.
func (q *Queue) Deny(id, reason string) bool {
	q.mu.Lock()
	h, ok := q.items[id]
	q.mu.Unlock()
	if !ok {
		return false
	}
	if reason == "" {
		reason = "operator denied"
	}
	h.resolveCh <- types.Decision{
		Effect: types.EffectAskUserResolvedDeny,
		Source: types.SourceApprovalQueue,
		RuleID: h.Decision.RuleID,
		Reason: reason,
	}
	if q.opLog != nil {
		q.opLog.Info("hold denied by operator",
			"event", oplog.EventHoldDenied,
			"hold_id", h.ID,
			"request_id", h.Request.ID,
			"identity", h.Request.IdentityID,
			"method", h.Request.Method,
			"scheme", h.Request.Scheme,
			"host", h.Request.Host,
			"port", h.Request.Port,
			"reason", reason)
	}
	return true
}

// Pending returns a JSON-friendly list of currently held requests
// in stable, oldest-first order (by CreatedAt, then by ID for the
// vanishingly rare tie). Stability matters because the TUI's
// approvals pane indexes the operator's selection into this slice;
// a reordered list moves the cursor under the operator and causes
// approve/deny to land on the wrong hold (closes #39).
func (q *Queue) Pending() []Snapshot {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Snapshot, 0, len(q.items))
	for _, h := range q.items {
		out = append(out, Snapshot{
			ID:         h.ID,
			CreatedAt:  h.CreatedAt,
			IdentityID: h.Request.IdentityID,
			Method:     h.Request.Method,
			Scheme:     h.Request.Scheme,
			Host:       h.Request.Host,
			Port:       h.Request.Port,
			Path:       h.Request.Path,
			Reason:     h.Decision.Reason,
			RuleID:     h.Decision.RuleID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Shutdown drains the queue, resolving every hold as a
// shutdown-deny.
func (q *Queue) Shutdown() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, h := range q.items {
		select {
		case h.resolveCh <- types.Decision{
			Effect: types.EffectAskUserResolvedDeny,
			Source: types.SourceApprovalTimeout,
			Reason: "trollbridge shutdown; approvals denied",
		}:
		default:
		}
	}
	q.items = map[string]*Hold{}
}

func (q *Queue) remove(id string) {
	q.mu.Lock()
	delete(q.items, id)
	q.mu.Unlock()
}
