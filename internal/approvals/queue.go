// Package approvals implements the held-request queue. See
// DESIGN.md §8.5.
package approvals

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
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
	// waiters are the resolution channels for every request coalesced
	// onto this hold (closes #206). The first request to enqueue a
	// given (identity, method, scheme, host, port, path) creates the
	// hold with one waiter; identical requests that arrive while it is
	// still pending attach an additional waiter rather than minting a
	// second hold. Resolution (Approve / Deny / advisor / timeout /
	// shutdown) broadcasts the single decision to every waiter, so the
	// operator decides once and every live retry is released together.
	// Each channel is cap-1 and written with a non-blocking send, so a
	// slow or dead waiter can never wedge resolution.
	waiters []chan types.Decision
	// dedupKey is the coalescing identity of the request (see
	// dedupKey()). Held so claim() can evict the byKey index entry.
	dedupKey string
	// resolved is set under Queue.mu by the first resolver that wins
	// the at-most-once claim (Approve / Deny / ResolveByAdvisor).
	// Subsequent resolvers see resolved=true and return false without
	// broadcasting or firing persistCb / lifecycle oplog.
	// Closes #55: prior code relied on the cap-1 channel for race
	// protection, but Wait can drain the channel between two
	// resolvers' lookups, letting the second push succeed and the
	// second persistCb fire — writing to both lists.allow and
	// lists.deny for a single operator action.
	resolved bool
}

// dedupKey is the coalescing identity of a held request: two requests
// share a hold iff they share this key. Identity is included so two
// different principals asking for the same URL stay separate rows; a
// principal retrying the same URL coalesces. NUL-joined because NUL
// cannot appear in any component, so the join is collision-free.
func dedupKey(req *types.RequestEvent) string {
	return strings.Join([]string{
		req.IdentityID, req.Method, req.Scheme,
		req.Host, strconv.Itoa(req.Port), req.Path,
	}, "\x00")
}

// broadcast delivers the resolved decision to every waiter coalesced
// onto the hold. Each send is non-blocking against a cap-1 channel, so
// a waiter that has already gone away (client disconnected, its Wait
// returned) cannot block the others.
func broadcast(h *Hold, d types.Decision) {
	for _, w := range h.waiters {
		select {
		case w <- d:
		default:
		}
	}
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
	// byKey indexes live (unresolved) holds by dedupKey so Enqueue can
	// coalesce an identical retry in O(1). Kept in lockstep with items
	// under mu: claim() and Shutdown() evict from both. By construction
	// at most one unresolved hold exists per key.
	byKey map[string]*Hold

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
		byKey:      map[string]*Hold{},
	}
}

// ErrFull is returned when the queue is at capacity.
var ErrFull = errors.New("approval queue full")

// claim returns the hold iff it exists and has not yet been resolved,
// atomically marking it resolved and evicting it from both indexes
// under Queue.mu. Returns nil otherwise. This is the at-most-once gate
// every resolver (Approve / Deny / ResolveByAdvisor / timeout /
// shutdown) passes through; only the winning caller proceeds to
// broadcast the decision and fire persistCb. Centralizing removal here
// (rather than in Wait) keeps items and byKey consistent and ensures a
// coalescing retry never attaches to a hold that is already resolving.
func (q *Queue) claim(id string) *Hold {
	q.mu.Lock()
	defer q.mu.Unlock()
	h, ok := q.items[id]
	if !ok || h.resolved {
		return nil
	}
	h.resolved = true
	delete(q.items, id)
	delete(q.byKey, h.dedupKey)
	return h
}

// Enqueue registers a request for operator action. Returns the hold ID,
// a channel that resolves with the operator's decision (or a
// timeout/shutdown deny), and whether the request coalesced onto an
// existing pending hold.
//
// Coalescing (closes #206): if an identical request — same dedupKey — is
// already pending, the new request attaches as an additional waiter on
// that hold instead of minting a second one. The returned id is the
// existing hold's, the channel is the new waiter's, and coalesced=true.
// The operator's single decision on that hold then releases every
// coalesced waiter. Coalescing is checked before the maxPending cap, so
// a retry for an already-pending URL is never rejected with ErrFull.
func (q *Queue) Enqueue(req *types.RequestEvent, baseDecision types.Decision) (id string, ch <-chan types.Decision, coalesced bool, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := dedupKey(req)
	if existing := q.byKey[key]; existing != nil && !existing.resolved {
		w := make(chan types.Decision, 1)
		existing.waiters = append(existing.waiters, w)
		return existing.ID, w, true, nil
	}
	if len(q.items) >= q.maxPending {
		return "", nil, false, ErrFull
	}
	id = "hold-" + uuid.NewString()
	w := make(chan types.Decision, 1)
	h := &Hold{
		ID:        id,
		Request:   req,
		Decision:  baseDecision,
		CreatedAt: time.Now().UTC(),
		waiters:   []chan types.Decision{w},
		dedupKey:  key,
	}
	q.items[id] = h
	q.byKey[key] = h
	return id, w, false, nil
}

// Wait blocks on the hold until resolution or the configured
// timeout elapses. The returned Decision will reflect the final
// outcome including timeout-deny / timeout-allow.
//
// reqCtx is the PER-REQUEST context for this waiter (closes #208). When
// it is canceled — the client disconnected — only THIS waiter is
// released: cancelWaiter removes it from the hold and evicts the hold
// only if it was the last waiter (freeing the max_pending slot). The
// hold is never resolved or denied on this path, so coalesced siblings
// keep waiting and the operator can still decide. Server shutdown is
// handled separately by Queue.Shutdown(), which broadcasts to every
// waiter (the `<-ch` case below), so callers that must NOT abandon on
// disconnect (the signal_after background wait) pass context.Background().
func (q *Queue) Wait(reqCtx context.Context, id string, ch <-chan types.Decision) types.Decision {
	timer := time.NewTimer(q.timeout)
	defer timer.Stop()
	select {
	case d := <-ch:
		// A resolver (Approve/Deny/advisor/timeout/shutdown) already
		// claimed the hold and removed it; we only collect our copy.
		return d
	case <-timer.C:
		eff := types.EffectAskUserTimedOut
		switch q.onTimeout {
		case "allow":
			eff = types.EffectAskUserResolvedAllow
		default:
			// timeout deny shows up explicitly so audit can
			// distinguish from a normal deny.
			eff = types.EffectAskUserTimedOut
		}
		d := types.Decision{
			Effect: eff,
			Source: types.SourceApprovalTimeout,
			Reason: fmt.Sprintf("approval timeout after %s", q.timeout),
		}
		// claim() evicts the hold and returns it iff this timer won the
		// race. The winner broadcasts the timeout to every coalesced
		// waiter so they all resolve together; losers (a concurrent
		// operator/advisor resolution) read the real decision off ch.
		h := q.claim(id)
		if h == nil {
			return <-ch
		}
		broadcast(h, d)
		if q.opLog != nil {
			q.opLog.Info("hold timed out",
				"event", oplog.EventHoldTimedOut,
				"hold_id", h.ID,
				"request_id", h.Request.ID,
				"identity", h.Request.IdentityID,
				"method", h.Request.Method,
				"scheme", h.Request.Scheme,
				"host", h.Request.Host,
				"port", h.Request.Port,
				"on_timeout", q.onTimeout,
				"timeout_seconds", int(q.timeout.Seconds()))
		}
		return d
	case <-reqCtx.Done():
		// This waiter's client disconnected (or canceled the request).
		// Release only this waiter — do not resolve the hold or deny the
		// coalesced siblings (#208). cancelWaiter removes this waiter
		// under mu and evicts the hold only if it was the last one.
		h, evicted, remaining := q.cancelWaiter(id, ch)
		if h == nil {
			// A resolver (operator / advisor / timeout / shutdown) won
			// the race and already claimed the hold; our decision is on
			// ch.
			return <-ch
		}
		if q.opLog != nil {
			q.opLog.Info("hold waiter abandoned by client",
				"event", oplog.EventHoldAbandoned,
				"hold_id", h.ID,
				"request_id", h.Request.ID,
				"identity", h.Request.IdentityID,
				"method", h.Request.Method,
				"scheme", h.Request.Scheme,
				"host", h.Request.Host,
				"port", h.Request.Port,
				"evicted", evicted,
				"remaining_waiters", remaining)
		}
		return types.Decision{
			Effect: types.EffectAskUserResolvedDeny,
			Source: types.SourceApprovalQueue,
			Reason: "client disconnected before approval",
		}
	}
}

// cancelWaiter releases a single waiter (its client disconnected) from
// hold id, identified by its resolution channel ch. It removes only
// that waiter; if the hold still has other waiters it stays pending and
// resolvable (coalesced siblings, #206). If ch was the LAST waiter, the
// hold is marked resolved and evicted from both indexes — freeing its
// max_pending slot — WITHOUT broadcasting a decision or firing persistCb
// (an abandonment is not an operator decision). Returns the (now possibly
// detached) hold for logging, whether it was evicted, and how many
// waiters remain. Returns (nil, false, 0) if a resolver already claimed
// the hold (the caller then reads its decision off ch).
func (q *Queue) cancelWaiter(id string, ch <-chan types.Decision) (h *Hold, evicted bool, remaining int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	hold, ok := q.items[id]
	if !ok || hold.resolved {
		return nil, false, 0
	}
	for i, w := range hold.waiters {
		if w == ch { // channel identity (bidirectional == recv-only)
			hold.waiters = append(hold.waiters[:i], hold.waiters[i+1:]...)
			break
		}
	}
	if len(hold.waiters) == 0 {
		hold.resolved = true
		delete(q.items, id)
		delete(q.byKey, hold.dedupKey)
		return hold, true, 0
	}
	return hold, false, len(hold.waiters)
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
	// claim() set resolved=true and evicted the hold under the lock, so
	// no concurrent resolver can compete for it; broadcast delivers the
	// one decision to every coalesced waiter (#206).
	broadcast(h, types.Decision{
		Effect:    types.EffectAskUserResolvedAllow,
		Source:    types.SourceApprovalQueue,
		RuleID:    h.Decision.RuleID,
		Reason:    "operator approved",
		Scope:     scope,
		Modifiers: append([]string(nil), h.Decision.Modifiers...),
	})
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
	broadcast(h, types.Decision{
		Effect: types.EffectAskUserResolvedDeny,
		Source: types.SourceApprovalQueue,
		RuleID: h.Decision.RuleID,
		Reason: reason,
	})
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
//
// **Alignment principle §1 (closes #193): an advisor-driven
// resolution NEVER fires the decision-persist callback.** The
// LLM may decide a single request — that is what releasing the
// hold does — but the operator's allow/deny lists are
// human-only. PersistCb is the path to lists.allow / lists.deny;
// only operator-driven Approve/Deny may take it. The audit log
// still records the LLM's verdict (Source=SourceLLMAdvisor); the
// YAML lists are not touched.
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
	broadcast(h, d)
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
	// Intentionally NO persistCb call here. See alignment principle
	// §1 above. Past code did fire persistCb with source="llm-advisor"
	// and that wrote to lists.allow / lists.deny; #193 is the closure
	// of that regression.
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

// Shutdown drains the queue, resolving every hold (and every waiter
// coalesced onto it, #206) as a shutdown-deny.
func (q *Queue) Shutdown() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, h := range q.items {
		if h.resolved {
			continue
		}
		h.resolved = true
		broadcast(h, types.Decision{
			Effect: types.EffectAskUserResolvedDeny,
			Source: types.SourceApprovalTimeout,
			Reason: "trollbridge shutdown; approvals denied",
		})
	}
	q.items = map[string]*Hold{}
	q.byKey = map[string]*Hold{}
}
