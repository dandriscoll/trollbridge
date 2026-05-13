package approvals

import (
	"context"
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
		id, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
	id, ch, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
	for i := 0; i < 2; i++ {
		if _, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser}); err == nil {
		t.Fatal("expected ErrFull")
	}
}

func TestApprove_ResolvesWait(t *testing.T) {
	q := New(8, time.Minute, "deny")
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser, RuleID: "r1"})

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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserTimedOut {
		t.Errorf("effect: got %s, want timed_out", d.Effect)
	}
}

func TestWait_TimesOutAsAllow_WhenConfigured(t *testing.T) {
	q := New(8, 50*time.Millisecond, "allow")
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAskUserResolvedAllow {
		t.Errorf("effect: got %s, want resolved_allow on allow timeout", d.Effect)
	}
}

func TestShutdown_ResolvesPendingAsDeny(t *testing.T) {
	q := New(8, time.Hour, "deny")
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
// assertions. Matches the approvals.Logger interface.
type recordingLogger struct {
	calls []logCall
}

type logCall struct {
	msg  string
	args []any
}

func (r *recordingLogger) Info(msg string, args ...any) {
	r.calls = append(r.calls, logCall{msg: msg, args: args})
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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id, "session", "test")
	_ = q.Wait(context.Background(), id, ch)
	if len(log.calls) != 1 {
		t.Fatalf("want 1 Info call, got %d (%v)", len(log.calls), log.calls)
	}
	if !hasArg(log.calls[0].args, "event", "hold_approved") {
		t.Errorf("event: %v", log.calls[0].args)
	}
	if !hasArg(log.calls[0].args, "hold_id", id) {
		t.Errorf("hold_id: %v", log.calls[0].args)
	}
	if !hasArg(log.calls[0].args, "scope", "session") {
		t.Errorf("scope: %v", log.calls[0].args)
	}
}

// TestQueue_DenyEmitsInfoEvent covers hold_denied.
func TestQueue_DenyEmitsInfoEvent(t *testing.T) {
	q := New(8, time.Minute, "deny")
	log := &recordingLogger{}
	q.SetLogger(log)
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Deny(id, "manual block", "test")
	_ = q.Wait(context.Background(), id, ch)
	if len(log.calls) != 1 || !hasArg(log.calls[0].args, "event", "hold_denied") {
		t.Errorf("expected one hold_denied Info; got %v", log.calls)
	}
	if !hasArg(log.calls[0].args, "reason", "manual block") {
		t.Errorf("reason missing: %v", log.calls[0].args)
	}
}

// TestQueue_TimeoutEmitsInfoEvent covers hold_timed_out.
func TestQueue_TimeoutEmitsInfoEvent(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	log := &recordingLogger{}
	q.SetLogger(log)
	_, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	id := q.Pending()[0].ID
	_ = q.Wait(context.Background(), id, ch)
	if len(log.calls) != 1 || !hasArg(log.calls[0].args, "event", "hold_timed_out") {
		t.Errorf("expected one hold_timed_out Info; got %v", log.calls)
	}
	if !hasArg(log.calls[0].args, "on_timeout", "deny") {
		t.Errorf("on_timeout missing: %v", log.calls[0].args)
	}
}

// TestQueue_NoLoggerDoesNotPanic asserts nil-safety when SetLogger
// is never called.
func TestQueue_NoLoggerDoesNotPanic(t *testing.T) {
	q := New(8, 50*time.Millisecond, "deny")
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
	var got []call
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		got = append(got, call{req: req, effect: effect, source: source})
	})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id, "once", "tui")
	_ = q.Wait(context.Background(), id, ch)
	// The Approve goroutine fires the callback synchronously after
	// the resolveCh send; give it a moment to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(got) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
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
	var lastEffect types.Effect
	var lastSource string
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		lastEffect = effect
		lastSource = source
	})
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Deny(id, "blocked by policy", "attach")
	_ = q.Wait(context.Background(), id, ch)
	deadline := time.Now().Add(500 * time.Millisecond)
	for lastSource == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

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
	if len(calls) != 1 {
		t.Fatalf("persistCb fired %d times, want 1: %v", len(calls), calls)
	}
	if calls[0] != types.EffectDeny {
		t.Errorf("persistCb effect = %v, want %v", calls[0], types.EffectDeny)
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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

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
	id, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})

	if !q.ResolveByAdvisor(id, types.Decision{Effect: types.EffectAllow}) {
		t.Fatal("ResolveByAdvisor returned false unexpectedly")
	}
	<-ch

	if q.Deny(id, "operator denied", "tui") {
		t.Errorf("Deny returned true after hold was advisor-resolved")
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

// TestQueue_PersistCallbackDoesNotFireOnTimeout — auto-resolution
// must not persist (only manual decisions should). Closes the design's
// "auto-allow timeout case" edge case.
func TestQueue_PersistCallbackDoesNotFireOnTimeout(t *testing.T) {
	q := New(8, 50*time.Millisecond, "allow")
	var fired bool
	q.SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
		fired = true
	})
	_, ch, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
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
	id, ch, err := q.Enqueue(&types.RequestEvent{ID: "r1"}, types.Decision{Effect: types.EffectAskUser})
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

	id, ch, err := q.Enqueue(&types.RequestEvent{ID: "r1"}, types.Decision{Effect: types.EffectAskUser})
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
