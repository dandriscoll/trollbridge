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

// DecisionPersist is invoked after a manual operator decision lands.
// It runs on the proxy host (the queue lives in the proxy daemon's
// process) and is the single hook for persisting approve/deny
// decisions — both the local-TUI in-process path and the mTLS
// control-plane (`trollbridge attach`) path converge at the queue,
// so a single callback covers both.
//
// `effect` is `EffectAllow` for approve and `EffectDeny` for deny.
// `source` is `"tui"` for in-process or `"attach"` for control-plane;
// callers pass it explicitly so the persistence layer can attribute
// the change in oplog without inferring from goroutine identity.
//
// Auto-resolution paths (timeout, shutdown drain) bypass this hook:
// they send the resolution directly down `resolveCh` rather than
// calling Approve/Deny, so only manual decisions persist.
type DecisionPersist func(req *types.RequestEvent, effect types.Effect, source string)

// Hold is a request waiting for operator action.
type Hold struct {
	ID        string
	Request   *types.RequestEvent
	Decision  types.Decision    // the engine's ask_user decision; carries reason
	CreatedAt time.Time
	resolveCh chan types.Decision
	// resolved is set under Queue.mu by the first resolver that wins
	// the at-most-once claim (Approve / Deny / ResolveByAdvisor).
	// Subsequent resolvers see resolved=true and return false without
	// pushing to resolveCh or firing persistCb / lifecycle oplog.
	// Closes #55: prior code relied on the cap-1 channel for race
	// protection, but Wait can drain the channel between two
	// resolvers' lookups, letting the second push succeed and the
	// second persistCb fire — writing to both lists.allow and
	// lists.deny for a single operator action.
	resolved bool
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

	// persistCb, when set, fires synchronously after a manual
	// approve/deny lands. nil-safe.
	persistCb DecisionPersist
}

// SetLogger wires an optional logger that the queue uses to emit
// hold-lifecycle Info events.
func (q *Queue) SetLogger(l Logger) { q.opLog = l }

// SetDecisionPersist wires the post-decision persistence hook. See
// DecisionPersist.
func (q *Queue) SetDecisionPersist(cb DecisionPersist) { q.persistCb = cb }

// Reconfigure swaps the queue's hot-reloadable parameters at runtime.
// Closes #111 (the approvals slice). The new values apply to NEW
// holds; in-flight Wait() calls continue to use the timer they
// already armed (changing the timer mid-flight would risk dropping
// holds that the operator was about to act on).
//
// maxPending <= 0 is silently ignored to preserve construction-time
// validation; onTimeout outside {"deny","allow"} is also ignored.
func (q *Queue) Reconfigure(maxPending int, timeout time.Duration, onTimeout string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if maxPending > 0 {
		q.maxPending = maxPending
	}
	if timeout > 0 {
		q.timeout = timeout
	}
	switch onTimeout {
	case "allow", "deny":
		q.onTimeout = onTimeout
	}
}

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

// claim returns the hold iff it exists and has not yet been resolved,
// atomically marking it resolved under Queue.mu. Returns nil
// otherwise. This is the at-most-once gate every resolver
// (Approve / Deny / ResolveByAdvisor) passes through; only the
// winning caller proceeds to push on resolveCh and fire persistCb.
func (q *Queue) claim(id string) *Hold {
	q.mu.Lock()
	defer q.mu.Unlock()
	h, ok := q.items[id]
	if !ok || h.resolved {
		return nil
	}
	h.resolved = true
	return h
}

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
// false if the hold was not found OR was already resolved by another
// path (operator double-click, advisor goroutine winning the race).
// `source` is "tui" for an in-process operator UI approval or
// "attach" for an mTLS control-plane approval; it propagates to the
// DecisionPersist callback for source attribution in oplog.
func (q *Queue) Approve(id, scope, source string) bool {
	h := q.claim(id)
	if h == nil {
		return false
	}
	if scope == "" {
		scope = "once"
	}
	// claim() set resolved=true under the lock, so no concurrent
	// resolver can compete for this hold; the push is exclusive.
	// Keep select+default as belt-and-suspenders — a future regression
	// that leaves a stale value in resolveCh must not block here.
	select {
	case h.resolveCh <- types.Decision{
		Effect:    types.EffectAskUserResolvedAllow,
		Source:    types.SourceApprovalQueue,
		RuleID:    h.Decision.RuleID,
		Reason:    "operator approved",
		Scope:     scope,
		Modifiers: append([]string(nil), h.Decision.Modifiers...),
	}:
	default:
		return false
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
	if q.persistCb != nil {
		q.persistCb(h.Request, types.EffectAllow, source)
	}
	return true
}

// Deny resolves the hold with a deny decision. `source` is "tui" or
// "attach"; see Approve. Returns false if the hold was already
// resolved (race with another Approve/Deny/ResolveByAdvisor).
func (q *Queue) Deny(id, reason, source string) bool {
	h := q.claim(id)
	if h == nil {
		return false
	}
	if reason == "" {
		reason = "operator denied"
	}
	select {
	case h.resolveCh <- types.Decision{
		Effect: types.EffectAskUserResolvedDeny,
		Source: types.SourceApprovalQueue,
		RuleID: h.Decision.RuleID,
		Reason: reason,
	}:
	default:
		return false
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
	if q.persistCb != nil {
		q.persistCb(h.Request, types.EffectDeny, source)
	}
	return true
}

// ResolveByAdvisor pushes the advisor's full Decision into the
// hold's resolveCh non-blockingly. The advisor goroutine in
// holdAndWait calls this when it produces a confident allow/deny
// (closes #53). Returns false if the hold was not found OR was
// already resolved by another path (operator winning the race).
//
// The Decision the advisor produces carries Source=SourceLLMAdvisor
// and the AdvisorID it was emitted under, so the audit log
// attributes the resolution to the LLM rather than the queue.
func (q *Queue) ResolveByAdvisor(id string, d types.Decision) bool {
	h := q.claim(id)
	if h == nil {
		return false
	}
	// Preserve the original rule id if the advisor's decision did
	// not name one (the advisor speaks for itself; the rule that
	// triggered the hold still applies as context).
	if d.RuleID == "" {
		d.RuleID = h.Decision.RuleID
	}
	select {
	case h.resolveCh <- d:
	default:
		return false
	}
	if q.opLog != nil {
		q.opLog.Info("hold resolved by advisor",
			"event", oplog.EventHoldApproved, // reuse: same lifecycle slot
			"hold_id", h.ID,
			"request_id", h.Request.ID,
			"identity", h.Request.IdentityID,
			"method", h.Request.Method,
			"scheme", h.Request.Scheme,
			"host", h.Request.Host,
			"port", h.Request.Port,
			"effect", string(d.Effect),
			"advisor_id", d.AdvisorID,
			"resolved_by", "llm-advisor")
	}
	if q.persistCb != nil && (d.Effect == types.EffectAllow || d.Effect == types.EffectDeny) {
		q.persistCb(h.Request, d.Effect, "llm-advisor")
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
