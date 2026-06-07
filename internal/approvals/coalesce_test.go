package approvals

import (
	"context"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestEnqueue_CoalescesIdenticalPending pins #206: when the same URL is
// requested repeatedly while a prior request is still pending, the
// queue must list it once, not once per retry. Reproduces the issue's
// "~20 times" wall of identical rows.
func TestEnqueue_CoalescesIdenticalPending(t *testing.T) {
	q := New(100, time.Minute, "deny")
	var firstID string
	for i := 0; i < 20; i++ {
		id, ch, coalesced, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		if ch == nil {
			t.Fatalf("enqueue %d: nil channel", i)
		}
		if i == 0 {
			firstID = id
			if coalesced {
				t.Fatal("first enqueue should not be coalesced")
			}
			continue
		}
		if !coalesced {
			t.Errorf("enqueue %d: coalesced=false, want true (identical request already pending)", i)
		}
		if id != firstID {
			t.Errorf("enqueue %d: id=%s, want the existing hold id %s", i, id, firstID)
		}
	}
	if n := len(q.Pending()); n != 1 {
		t.Fatalf("Pending() len = %d, want 1 (same URL coalesced)", n)
	}
}

// TestEnqueue_ResolveBroadcastsToAllWaiters pins success-criterion #2:
// one operator decision releases every coalesced waiter with the same
// outcome — no retry is left hanging until timeout. Fails if broadcast
// is reduced to a single-waiter send.
func TestEnqueue_ResolveBroadcastsToAllWaiters(t *testing.T) {
	q := New(100, time.Minute, "deny")
	const n = 4
	chans := make([]<-chan types.Decision, n)
	var holdID string
	for i := 0; i < n; i++ {
		id, ch, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser, RuleID: "r1"})
		if err != nil {
			t.Fatal(err)
		}
		holdID, chans[i] = id, ch
	}
	if got := len(q.Pending()); got != 1 {
		t.Fatalf("Pending() len = %d, want 1", got)
	}

	results := make(chan types.Decision, n)
	for _, ch := range chans {
		go func(c <-chan types.Decision) {
			results <- q.Wait(context.Background(), holdID, c)
		}(ch)
	}
	// Let the waiters arm before the single operator approve.
	time.Sleep(10 * time.Millisecond)
	if !q.Approve(holdID, "session", "tui") {
		t.Fatal("Approve returned false")
	}

	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case d := <-results:
			if d.Effect != types.EffectAskUserResolvedAllow {
				t.Errorf("waiter %d effect = %s, want resolved_allow", i, d.Effect)
			}
			if d.Scope != "session" {
				t.Errorf("waiter %d scope = %q, want session", i, d.Scope)
			}
		case <-deadline:
			t.Fatalf("only %d of %d coalesced waiters resolved; the rest are hung", i, n)
		}
	}
	// The hold is gone after resolution.
	if got := len(q.Pending()); got != 0 {
		t.Errorf("Pending() len = %d after approve, want 0", got)
	}
}

// TestEnqueue_DistinctRequestsStayDistinct guards against over-
// coalescing: requests that differ in any dedupKey component must keep
// separate rows.
func TestEnqueue_DistinctRequestsStayDistinct(t *testing.T) {
	q := New(100, time.Minute, "deny")
	reqs := []*types.RequestEvent{
		{IdentityID: "id-1", Method: "GET", Scheme: "https", Host: "a.com", Port: 443, Path: "/x"},
		{IdentityID: "id-1", Method: "POST", Scheme: "https", Host: "a.com", Port: 443, Path: "/x"},   // method differs
		{IdentityID: "id-1", Method: "GET", Scheme: "https", Host: "a.com", Port: 443, Path: "/y"},     // path differs
		{IdentityID: "id-1", Method: "GET", Scheme: "https", Host: "b.com", Port: 443, Path: "/x"},     // host differs
		{IdentityID: "id-2", Method: "GET", Scheme: "https", Host: "a.com", Port: 443, Path: "/x"},     // identity differs
		{IdentityID: "id-1", Method: "GET", Scheme: "https", Host: "a.com", Port: 8443, Path: "/x"},    // port differs
		{IdentityID: "id-1", Method: "GET", Scheme: "http", Host: "a.com", Port: 443, Path: "/x"},      // scheme differs
	}
	for i, r := range reqs {
		_, _, coalesced, err := q.Enqueue(r, types.Decision{Effect: types.EffectAskUser})
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		if coalesced {
			t.Errorf("request %d coalesced but is distinct: %+v", i, r)
		}
	}
	if n := len(q.Pending()); n != len(reqs) {
		t.Errorf("Pending() len = %d, want %d (all distinct)", n, len(reqs))
	}
}

// TestEnqueue_TimeoutBroadcastsToAllWaiters pins that auto-resolution
// (timeout) also releases every coalesced waiter together, not just the
// one whose timer fired.
func TestEnqueue_TimeoutBroadcastsToAllWaiters(t *testing.T) {
	q := New(100, 60*time.Millisecond, "deny")
	const n = 3
	chans := make([]<-chan types.Decision, n)
	var holdID string
	for i := 0; i < n; i++ {
		id, ch, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
		if err != nil {
			t.Fatal(err)
		}
		holdID, chans[i] = id, ch
	}
	results := make(chan types.Decision, n)
	for _, ch := range chans {
		go func(c <-chan types.Decision) {
			results <- q.Wait(context.Background(), holdID, c)
		}(ch)
	}
	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case d := <-results:
			if d.Effect != types.EffectAskUserTimedOut {
				t.Errorf("waiter %d effect = %s, want timed_out", i, d.Effect)
			}
		case <-deadline:
			t.Fatalf("only %d of %d coalesced waiters timed out; the rest are hung", i, n)
		}
	}
}

// TestEnqueue_CoalesceBypassesMaxPending pins that a retry for an
// already-pending URL coalesces even when the queue is at capacity — it
// must not be rejected with ErrFull (it does not grow the visible queue).
func TestEnqueue_CoalesceBypassesMaxPending(t *testing.T) {
	q := New(2, time.Minute, "deny")
	// Fill to capacity with two distinct requests.
	if _, _, _, err := q.Enqueue(newReqN(1), types.Decision{Effect: types.EffectAskUser}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := q.Enqueue(newReqN(2), types.Decision{Effect: types.EffectAskUser}); err != nil {
		t.Fatal(err)
	}
	// A retry of an already-pending URL must coalesce, not hit ErrFull.
	_, _, coalesced, err := q.Enqueue(newReqN(1), types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatalf("retry of pending URL hit error %v; want coalesce", err)
	}
	if !coalesced {
		t.Error("retry at capacity should coalesce, not mint a new hold")
	}
	// A genuinely new URL at capacity still hits ErrFull.
	if _, _, _, err := q.Enqueue(newReqN(3), types.Decision{Effect: types.EffectAskUser}); err != ErrFull {
		t.Errorf("new URL at capacity: err = %v, want ErrFull", err)
	}
}

// TestEnqueue_CoalesceAfterResolveStartsFreshHold pins that once a hold
// resolves and is evicted, the next identical request starts a new hold
// rather than attaching to the dead one.
func TestEnqueue_CoalesceAfterResolveStartsFreshHold(t *testing.T) {
	q := New(100, time.Minute, "deny")
	id1, ch1, _, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	go q.Approve(id1, "once", "tui")
	if d := q.Wait(context.Background(), id1, ch1); d.Effect != types.EffectAskUserResolvedAllow {
		t.Fatalf("first resolve effect = %s", d.Effect)
	}
	// Same URL again: the prior hold is gone, so this is a fresh hold.
	id2, _, coalesced, _ := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if coalesced {
		t.Error("enqueue after resolution coalesced onto a dead hold")
	}
	if id2 == id1 {
		t.Errorf("new hold id %s equals the resolved hold id", id2)
	}
	if n := len(q.Pending()); n != 1 {
		t.Errorf("Pending() len = %d, want 1", n)
	}
}
