package policy

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
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

// TestHistory_DoesNotRecordLLMVerdicts closes #141: a prior_decision
// match clause must not match a prior LLM verdict — that would
// create a second unaudited LLM-feedback path (the advisor decides
// once, a deterministic rule re-applies the decision later without
// re-consulting). History.Record drops SourceLLMAdvisor entries at
// the recording boundary; the match surface stays scoped to human +
// static-policy decisions.
func TestHistory_DoesNotRecordLLMVerdicts(t *testing.T) {
	h := NewHistory(64)
	now := time.Now().UTC()

	// A prior LLM verdict for the same identity + host + effect.
	h.Record(&types.RequestEvent{IdentityID: "alice", Host: "x.com"},
		types.Decision{
			Effect: types.EffectDeny,
			Source: types.SourceLLMAdvisor,
		},
		now.Add(-10*time.Second))

	m := &PriorDecisionMatch{Effect: "deny", SameIdentity: true, SameHost: true, WithinSeconds: 60}
	if h.Match(&types.RequestEvent{IdentityID: "alice", Host: "x.com"}, m, now) {
		t.Error("prior LLM verdict should not match prior_decision; expected no match")
	}
	if got := len(h.buf); got != 0 {
		t.Errorf("buf len after LLM-only Record: got %d, want 0 (LLM verdicts must not be recorded)", got)
	}

	// Static-policy verdicts still record + match.
	h.Record(&types.RequestEvent{IdentityID: "alice", Host: "x.com"},
		types.Decision{
			Effect: types.EffectDeny,
			Source: types.SourceRule,
			RuleID: "r1",
		},
		now.Add(-10*time.Second))
	if !h.Match(&types.RequestEvent{IdentityID: "alice", Host: "x.com"}, m, now) {
		t.Error("static-policy verdict should match prior_decision")
	}
}
