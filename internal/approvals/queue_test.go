package approvals

import (
	"context"
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
	go q.Approve(id, "session")
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
	go q.Deny(id, "manual block")
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
	go q.Approve(id, "")
	_ = q.Wait(context.Background(), id, ch)
	// Reaching here is the assertion.
}
