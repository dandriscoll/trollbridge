package approvals

import (
	"context"
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/types"
)

func newReq() *types.RequestEvent {
	return &types.RequestEvent{
		Host: "example.com", Port: 443, Method: "GET", Path: "/",
		IdentityID: "id-1",
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
		if !q.Approve(id, "session") {
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
	go q.Deny(id, "spam")
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
