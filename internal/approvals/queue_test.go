package approvals

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

func newReq() *types.RequestEvent {
	return &types.RequestEvent{
		Host: "example.com", Port: 443, Method: "GET", Path: "/",
		IdentityID: "id-1",
	}
}

// newReqN returns a request with a distinct dedupKey (unique path) so
// that, after the #206 coalescing change, each Enqueue produces its own
// hold. Tests whose intent is ordering or capacity — not dedup — use
// this so identical requests don't silently collapse to one row.
func newReqN(i int) *types.RequestEvent {
	return &types.RequestEvent{
		Host: "example.com", Port: 443, Method: "GET",
		Path:       fmt.Sprintf("/p%d", i),
		IdentityID: "id-1",
	}
}

// TestPending_StableOrderAcrossCalls pins the contract behind the
// fix for #39: `Pending()` must return holds in a stable
// oldest-first order so the TUI's selection-by-index does not jump
// when nothing has changed. Pre-fix, `for _, h := range q.items`
// over a Go map produced a different order on every call.
func TestPending_StableOrderAcrossCalls(t *testing.T) {
	q := New(16, time.Minute, "deny")
	// Enqueue with a forced 1ms gap so CreatedAt orders unambiguously.
	want := []string{}
	for i := 0; i < 5; i++ {
		// Distinct requests: this test pins ordering, not dedup; identical
		// requests would coalesce to a single hold after #206.
		id, _, _, err := q.Enqueue(newReqN(i), types.Decision{Effect: types.EffectAskUser})
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		want = append(want, id)
		time.Sleep(time.Millisecond)
	}
	first := q.Pending()
	if len(first) != len(want) {
		t.Fatalf("len(first) = %d, want %d", len(first), len(want))
	}
	for i, h := range first {
		if h.ID != want[i] {
			t.Errorf("first[%d].ID = %s, want %s (oldest-first)", i, h.ID, want[i])
		}
	}
	// Call Pending() many times; every call must return the same
	// order. Pre-fix this would flake on map-iteration randomness.
	for round := 0; round < 50; round++ {
		got := q.Pending()
		for i := range got {
			if got[i].ID != first[i].ID {
				t.Fatalf("round %d index %d: got %s want %s", round, i, got[i].ID, first[i].ID)
			}
		}
	}
}

func TestEnqueue_ReturnsHoldID(t *testing.T) {
	q := New(8, time.Minute, "deny")
	id, ch, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || ch == nil {
		t.Fatal("expected hold id and channel")
	}
	if got := q.Pending(); len(got) != 1 || got[0].ID != id {
		t.Errorf("Pending: got %+v, want one with id=%s", got, id)
	}
}

func TestEnqueue_FullReturnsErrFull(t *testing.T) {
	q := New(2, time.Minute, "deny")
	// Distinct requests so each consumes a slot; identical ones would
	// coalesce and never reach the cap (#206).
	for i := 0; i < 2; i++ {
		if _, _, _, err := q.Enqueue(newReqN(i), types.Decision{Effect: types.EffectAskUser}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := q.Enqueue(newReqN(99), types.Decision{Effect: types.EffectAskUser}); err == nil {
		t.Fatal("expected ErrFull")
	}
}

func TestApprove_ResolvesWait(t *testing.T) {
	q := New(8, time.Minute, "deny")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser, RuleID: "r1"})

	go func() {
		time.Sleep(10 * time.Millisecond)
		if !q.Approve(id, "session", "test") {
			t.Errorf("Approve returned false")
		}
	}()

	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedAllow {
		t.Errorf("effect: got %s, want ask_user_resolved_allow", d.Effect)
	}
	if d.Scope != "session" {
		t.Errorf("scope: got %s, want session", d.Scope)
	}
}

func TestDeny_ResolvesWait(t *testing.T) {
	q := New(8, time.Minute, "deny")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Deny(id, "spam", "test")
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedDeny {
		t.Errorf("effect: got %s, want resolved_deny", d.Effect)
	}
	if d.Reason != "spam" {
		t.Errorf("reason: got %q", d.Reason)
	}
}

func TestWait_TimesOutAsDeny(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserTimedOut {
		t.Errorf("effect: got %s, want timed_out", d.Effect)
	}
}

func TestWait_TimesOutAsAllow_WhenConfigured(t *testing.T) {
	q := New(8, 50*time.Millisecond, "allow")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedAllow {
		t.Errorf("effect: got %s, want resolved_allow on allow timeout", d.Effect)
	}
}

func TestShutdown_ResolvesPendingAsDeny(t *testing.T) {
	q := New(8, time.Hour, "deny")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go func() {
		time.Sleep(10 * time.Millisecond)
		q.Shutdown()
	}()
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedDeny {
		t.Errorf("effect: got %s, want resolved_deny on shutdown", d.Effect)
	}
}

// recordingLogger captures Info invocations for queue lifecycle
// assertions. Matches the approvals.Logger interface. Thread-safe: the
// queue emits these from the resolving goroutine (Approve/Deny run via
// `go`), so the append races the test's read without the mutex.
type recordingLogger struct {
	mu    sync.Mutex
	calls []logCall
}

type logCall struct {
	msg  string
	args []any
}

func (r *recordingLogger) Info(msg string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, logCall{msg: msg, args: args})
}

// snap returns a copy of the recorded calls for race-free assertions.
func (r *recordingLogger) snap() []logCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]logCall(nil), r.calls...)
}

func hasArg(args []any, key, valueContains string) bool {
	for i := 0; i+1 < len(args); i += 2 {
		k, _ := args[i].(string)
		if k != key {
			continue
		}
		switch v := args[i+1].(type) {
		case string:
			if valueContains == "" || contains(v, valueContains) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestQueue_ApproveEmitsInfoEvent closes the hold_approved INFO
// requirement of issue #36.
func TestQueue_ApproveEmitsInfoEvent(t *testing.T) {
	q := New(8, time.Minute, "deny")
	log := &recordingLogger{}
	q.SetLogger(log)
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id, "session", "test")
	_ = q.Wait(context.Background(), id, ch)
	// Approve broadcasts the decision BEFORE it emits the Info log;
	// Wait can return before the log call lands. Poll briefly so this
	// test is not racy on slow CI runners (Windows lane in particular).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(log.snap()) < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	calls := log.snap()
	if len(calls) != 1 {
		t.Fatalf("want 1 Info call, got %d (%v)", len(calls), calls)
	}
	if !hasArg(calls[0].args, "event", "hold_approved") {
		t.Errorf("event: %v", calls[0].args)
	}
	if !hasArg(calls[0].args, "hold_id", id) {
		t.Errorf("hold_id: %v", calls[0].args)
	}
	if !hasArg(calls[0].args, "scope", "session") {
		t.Errorf("scope: %v", calls[0].args)
	}
}

// TestQueue_DenyEmitsInfoEvent covers hold_denied.
func TestQueue_DenyEmitsInfoEvent(t *testing.T) {
	q := New(8, time.Minute, "deny")
	log := &recordingLogger{}
	q.SetLogger(log)
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Deny(id, "manual block", "test")
	_ = q.Wait(context.Background(), id, ch)
	// Same race as TestQueue_ApproveEmitsInfoEvent — Deny broadcasts the
	// decision before emitting Info; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(log.snap()) < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	calls := log.snap()
	if len(calls) != 1 || !hasArg(calls[0].args, "event", "hold_denied") {
		t.Errorf("expected one hold_denied Info; got %v", calls)
	}
	if !hasArg(calls[0].args, "reason", "manual block") {
		t.Errorf("reason missing: %v", calls[0].args)
	}
}

// TestQueue_TimeoutEmitsInfoEvent covers hold_timed_out.
func TestQueue_TimeoutEmitsInfoEvent(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	log := &recordingLogger{}
	q.SetLogger(log)
	_, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	id := q.Pending()[0].ID
	_ = q.Wait(context.Background(), id, ch)
	calls := log.snap()
	if len(calls) != 1 || !hasArg(calls[0].args, "event", "hold_timed_out") {
		t.Errorf("expected one hold_timed_out Info; got %v", calls)
	}
	if !hasArg(calls[0].args, "on_timeout", "deny") {
		t.Errorf("on_timeout missing: %v", calls[0].args)
	}
}

// TestQueue_NoLoggerDoesNotPanic asserts nil-safety when SetLogger
// is never called.
func TestQueue_NoLoggerDoesNotPanic(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id, "", "test")
	_ = q.Wait(context.Background(), id, ch)
	// Reaching here is the assertion.
}

// TestQueue_PersistCallbackFiresOnApprove pins #49: after a manual
// approve, the DecisionPersist callback runs with the held request,
// EffectAllow, and the source string the caller passed.
func TestQueue_PersistCallbackFiresOnApprove(t *testing.T) {
	q := New(8, time.Minute, "deny")
	type call struct {
		req    *types.RequestEvent
		effect types.Effect
		source string
	}
	// The callback fires on the Deny/Approve goroutine; guard the shared
	// captures so this test is clean under -race (the assertions read
	// the same fields the callback writes).
	var mu sync.Mutex
	var got []call
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, call{req: req, effect: effect, source: source})
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id, "once", "tui")
	_ = q.Wait(context.Background(), id, ch)
	// The Approve goroutine fires the callback synchronously after
	// the broadcast send; give it a moment to land.
	gotLen := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	deadline := time.Now().Add(500 * time.Millisecond)
	for gotLen() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("persist callback fired %d time(s); want 1", len(got))
	}
	if got[0].effect != types.EffectAllow {
		t.Errorf("effect = %v, want %v", got[0].effect, types.EffectAllow)
	}
	if got[0].source != "tui" {
		t.Errorf("source = %q, want %q", got[0].source, "tui")
	}
	if got[0].req == nil || got[0].req.Host == "" {
		t.Errorf("req or req.Host missing: %+v", got[0].req)
	}
}

// TestQueue_PersistCallbackFiresOnDeny — symmetric to approve.
func TestQueue_PersistCallbackFiresOnDeny(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var mu sync.Mutex
	var lastEffect types.Effect
	var lastSource string
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		mu.Lock()
		defer mu.Unlock()
		lastEffect = effect
		lastSource = source
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Deny(id, "blocked by policy", "attach")
	_ = q.Wait(context.Background(), id, ch)
	readSource := func() string { mu.Lock(); defer mu.Unlock(); return lastSource }
	deadline := time.Now().Add(500 * time.Millisecond)
	for readSource() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if lastEffect != types.EffectDeny {
		t.Errorf("effect = %v, want %v", lastEffect, types.EffectDeny)
	}
	if lastSource != "attach" {
		t.Errorf("source = %q, want %q", lastSource, "attach")
	}
}

// TestQueue_ApproveAfterAdvisorResolved_DoesNotDoubleFire pins #55.
// Scenario: the advisor resolves a hold with EffectDeny; Wait drains
// the channel and removes the hold from q.items shortly after; the
// operator presses 'a' on the same row while Approve's lookup races
// with remove. The legacy code allowed Approve's push to succeed
// against the now-empty channel and fire a second persistCb,
// adding the URL to lists.allow even though the advisor had already
// added it to lists.deny.
//
// This test simulates the race by manually draining the channel
// (the queue's Wait normally does this) without calling remove,
// then invoking Approve. Without the resolved-flag claim, Approve
// would push successfully and fire persistCb with EffectAllow;
// with the claim, Approve returns false and persistCb stays at one
// invocation.
func TestQueue_ApproveAfterAdvisorResolved_DoesNotDoubleFire(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []types.Effect
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, e types.Effect, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, e)
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectDeny}) {
		t.Fatal("ResolveByAdvisor returned false unexpectedly")
	}
	// Simulate Wait having read the resolveCh; do NOT remove the hold,
	// reproducing the race window where another resolver finds the hold
	// still in q.items but the channel is empty.
	<-ch

	if q.Approve(id, "once", "tui") {
		t.Errorf("Approve returned true after hold was advisor-resolved")
	}
	mu.Lock()
	defer mu.Unlock()
	// #193: an advisor-driven resolve does NOT fire persistCb (only
	// operator-driven approve/deny does). Approve here returns false
	// because the hold is already resolved, so persistCb stays at 0.
	// The at-most-once contract is preserved (0 fires <= 1).
	if len(calls) != 0 {
		t.Fatalf("persistCb fired %d times after advisor-Deny then Approve-rejected; want 0 (LLM never persists; Approve was rejected). calls=%v", len(calls), calls)
	}
}

// TestQueue_AdvisorAfterApprove_DoesNotDoubleFire is the symmetric
// direction of #55: operator approves, Wait drains, advisor's
// callback finishes later and tries to resolve. Must not fire a
// second persistCb / second lifecycle log.
func TestQueue_AdvisorAfterApprove_DoesNotDoubleFire(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []types.Effect
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, e types.Effect, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, e)
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

	if !q.Approve(id, "once", "tui") {
		t.Fatal("Approve returned false unexpectedly")
	}
	<-ch

	if q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectDeny}) {
		t.Errorf("ResolveByAdvisor returned true after operator already approved")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("persistCb fired %d times, want 1: %v", len(calls), calls)
	}
	if calls[0] != types.EffectAllow {
		t.Errorf("persistCb effect = %v, want %v", calls[0], types.EffectAllow)
	}
}

// TestQueue_DenyAfterAdvisorResolved_DoesNotDoubleFire covers the
// Deny path's at-most-once gate (#55 sibling).
func TestQueue_DenyAfterAdvisorResolved_DoesNotDoubleFire(t *testing.T) {
	q := New(8, time.Minute, "deny")
	var (
		mu    sync.Mutex
		calls []types.Effect
	)
	q.SetDecisionPersist(func(_ *types.RequestEvent, e types.Effect, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, e)
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectAllow}) {
		t.Fatal("ResolveByAdvisor returned false unexpectedly")
	}
	<-ch

	if q.Deny(id, "operator denied", "tui") {
		t.Errorf("Deny returned true after hold was advisor-resolved")
	}
	mu.Lock()
	defer mu.Unlock()
	// #193: an advisor-driven resolve does NOT fire persistCb. Deny
	// here returns false because the hold is already resolved, so
	// persistCb stays at 0. The at-most-once contract is preserved.
	if len(calls) != 0 {
		t.Fatalf("persistCb fired %d times after advisor-Allow then Deny-rejected; want 0 (LLM never persists; Deny was rejected). calls=%v", len(calls), calls)
	}
}

// TestQueue_PersistCallbackDoesNotFireOnTimeout — auto-resolution
// must not persist (only manual decisions should). Closes the design's
// "auto-allow timeout case" edge case.
func TestQueue_PersistCallbackDoesNotFireOnTimeout(t *testing.T) {
	q := New(8, 50*time.Millisecond, "allow")
	var fired bool
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		fired = true
	})
	_, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	id := q.Pending()[0].ID
	_ = q.Wait(context.Background(), id, ch)
	// Give the callback a moment in case the deny path mistakenly invokes it.
	time.Sleep(100 * time.Millisecond)
	if fired {
		t.Errorf("persist callback fired on auto-timeout; should fire only on manual approve/deny")
	}
}

// TestQueue_Reconfigure_NewTimeoutAffectsNewWaits closes #111
// (approvals slice). Reconfigure swaps the queue's timeout for new
// holds; in-flight Wait calls keep their original timer.
func TestQueue_Reconfigure_NewTimeoutAffectsNewWaits(t *testing.T) {
	q := New(8, 5*time.Second, "deny")

	// Reduce the timeout via Reconfigure.
	q.Reconfigure(8, 100*time.Millisecond, "deny")

	// New hold uses the new timeout.
	id, ch, _, err := q.Enqueue(&types.RequestEvent{ID: "r1"}, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d := q.Wait(context.Background(), id, ch)
	elapsed := time.Since(start)
	if d.Effect != types.EffectAskUserTimedOut {
		t.Errorf("effect = %s, want EffectAskUserTimedOut", d.Effect)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took %v; expected ~100ms after Reconfigure", elapsed)
	}
}

// TestQueue_Reconfigure_OnTimeoutSwap covers the on_timeout flip.
func TestQueue_Reconfigure_OnTimeoutSwap(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	q.Reconfigure(8, 50*time.Millisecond, "allow")

	id, ch, _, err := q.Enqueue(&types.RequestEvent{ID: "r1"}, types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedAllow {
		t.Errorf("effect = %s, want EffectAskUserResolvedAllow (on_timeout=allow)", d.Effect)
	}
}

// TestQueue_Reconfigure_IgnoresInvalidValues defends against a
// malformed config edit clobbering live parameters.
func TestQueue_Reconfigure_IgnoresInvalidValues(t *testing.T) {
	q := New(16, 5*time.Second, "deny")
	q.Reconfigure(0, 0, "")           // all zeros — should be ignored
	q.Reconfigure(8, time.Second, "garbage") // invalid onTimeout — keep prior

	// Verify the new fields apply where valid (max + timeout) and
	// the invalid onTimeout was ignored.
	if q.maxPending != 8 {
		t.Errorf("maxPending = %d, want 8", q.maxPending)
	}
	if q.timeout != time.Second {
		t.Errorf("timeout = %v, want 1s", q.timeout)
	}
	if q.onTimeout != "deny" {
		t.Errorf("onTimeout = %q, want preserved 'deny'", q.onTimeout)
	}
}

// --- #208: per-waiter release on client (request-context) cancel ---

// TestQueue_WaitReleasesAndEvictsOnRequestCancel pins #208: when the
// sole waiter's request context cancels (client disconnected), Wait
// returns promptly with a deny (NOT after timeout), the hold is evicted
// (slot freed), and the decision-persist callback does NOT fire (an
// abandonment is not an operator decision).
func TestQueue_WaitReleasesAndEvictsOnRequestCancel(t *testing.T) {
	q := New(8, time.Minute, "deny") // long timeout: only the cancel can release
	var persisted int
	var pmu sync.Mutex
	q.SetDecisionPersist(func(_ *types.RequestEvent, _ types.Effect, _ string) {
		pmu.Lock()
		persisted++
		pmu.Unlock()
	})
	id, ch, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if len(q.Pending()) != 1 {
		t.Fatalf("hold not pending after enqueue")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan types.Decision, 1)
	start := time.Now()
	go func() { done <- q.Wait(ctx, id, ch) }()
	cancel()
	select {
	case d := <-done:
		if time.Since(start) > 2*time.Second {
			t.Errorf("Wait took %v; should return promptly on request cancel, not at timeout", time.Since(start))
		}
		if d.Effect != types.EffectAskUserResolvedDeny {
			t.Errorf("effect = %s, want resolved_deny (client disconnected)", d.Effect)
		}
		if d.Reason != "client disconnected before approval" {
			t.Errorf("reason = %q", d.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not return on request-context cancel (waiter pinned)")
	}
	if len(q.Pending()) != 0 {
		t.Errorf("hold not evicted after last waiter canceled; Pending=%d", len(q.Pending()))
	}
	pmu.Lock()
	defer pmu.Unlock()
	if persisted != 0 {
		t.Errorf("persistCb fired %d time(s) on abandonment; want 0", persisted)
	}
}

// TestQueue_CancelWaiterKeepsHoldForSiblings pins #208 + #206: when one
// coalesced waiter's client disconnects, only that waiter is released;
// the hold stays pending for the remaining sibling and the operator can
// still approve it (the sibling resolves allow).
func TestQueue_CancelWaiterKeepsHoldForSiblings(t *testing.T) {
	q := New(8, time.Minute, "deny")
	req := newReq()
	id1, ch1, c1, _ := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	id2, ch2, c2, _ := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser})
	if c1 || !c2 || id1 != id2 {
		t.Fatalf("expected second identical request to coalesce: c1=%v c2=%v id1=%s id2=%s", c1, c2, id1, id2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	gone := make(chan types.Decision, 1)
	go func() { gone <- q.Wait(ctx, id1, ch1) }() // first waiter: cancelable
	stay := make(chan types.Decision, 1)
	go func() { stay <- q.Wait(context.Background(), id2, ch2) }() // sibling: stays

	cancel() // first client disconnects
	select {
	case d := <-gone:
		if d.Reason != "client disconnected before approval" {
			t.Errorf("first waiter: reason = %q", d.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first waiter not released on cancel")
	}

	// The hold must remain — a sibling is still waiting.
	if len(q.Pending()) != 1 {
		t.Fatalf("hold evicted despite a remaining sibling; Pending=%d", len(q.Pending()))
	}

	// Operator approves; the surviving sibling resolves allow.
	if !q.Approve(id2, "once", "tui") {
		t.Fatalf("approve failed; hold went missing")
	}
	select {
	case d := <-stay:
		if d.Effect != types.EffectAskUserResolvedAllow {
			t.Errorf("sibling effect = %s, want resolved_allow", d.Effect)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("surviving sibling not resolved by operator approve")
	}
}
