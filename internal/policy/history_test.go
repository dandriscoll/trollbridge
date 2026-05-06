package policy

import (
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/types"
)

func TestHistory_MatchesSameIdentitySameHostWithinWindow(t *testing.T) {
	h := NewHistory(64)
	now := time.Now().UTC()
	h.Record(&types.RequestEvent{IdentityID: "alice", Host: "x.com"},
		types.Decision{Effect: types.EffectDeny, RuleID: "r"}, now.Add(-30*time.Second))

	m := &PriorDecisionMatch{
		Effect: "deny", SameIdentity: true, SameHost: true, WithinSeconds: 60,
	}
	if !h.Match(&types.RequestEvent{IdentityID: "alice", Host: "x.com"}, m, now) {
		t.Error("expected match for same identity, same host, within 60s")
	}
}

func TestHistory_RejectsOutsideWindow(t *testing.T) {
	h := NewHistory(64)
	now := time.Now().UTC()
	h.Record(&types.RequestEvent{IdentityID: "alice", Host: "x.com"},
		types.Decision{Effect: types.EffectDeny}, now.Add(-300*time.Second))
	m := &PriorDecisionMatch{
		Effect: "deny", SameIdentity: true, SameHost: true, WithinSeconds: 60,
	}
	if h.Match(&types.RequestEvent{IdentityID: "alice", Host: "x.com"}, m, now) {
		t.Error("expected no match outside window")
	}
}

func TestHistory_DifferentIdentityDoesNotMatch(t *testing.T) {
	h := NewHistory(64)
	now := time.Now().UTC()
	h.Record(&types.RequestEvent{IdentityID: "alice", Host: "x.com"},
		types.Decision{Effect: types.EffectDeny}, now.Add(-10*time.Second))
	m := &PriorDecisionMatch{Effect: "deny", SameIdentity: true, WithinSeconds: 60}
	if h.Match(&types.RequestEvent{IdentityID: "bob", Host: "x.com"}, m, now) {
		t.Error("expected no match for different identity")
	}
}

func TestHistory_BoundedCapacity(t *testing.T) {
	h := NewHistory(2)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		h.Record(&types.RequestEvent{IdentityID: "x", Host: "x.com"},
			types.Decision{Effect: types.EffectAllow}, now)
	}
	// Should not panic; internal buf bounded to 2.
	if got := len(h.buf); got > 2 {
		t.Errorf("buf len: got %d, want <=2", got)
	}
}
