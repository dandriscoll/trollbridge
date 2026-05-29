package policy

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestHasOppositeEffect_NormalizesAskUserResolvedEffects pins
// the fix for #192 reopen: operator-resolved decisions record
// with Effect="ask_user_resolved_allow"/_deny (the literal
// EffectAskUserResolved{Allow,Deny} values). HasOppositeEffect
// must normalize these to "allow"/"deny" before comparison so
// the TUI's reversal-coloring lookup (which passes the
// abbreviated form) gets correct answers.
//
// Pre-fix: HasOppositeEffect did straight string compare;
// "ask_user_resolved_deny" != "allow" → returned true even when
// the current direction matched (false positive in this fixture).
// Post-fix: normalized to "deny" → returns true correctly.
func TestHasOppositeEffect_NormalizesAskUserResolvedEffects(t *testing.T) {
	h := NewHistory(64)
	req := &types.RequestEvent{Host: "example.com", IdentityID: "id-1"}
	now := time.Now().UTC()
	// Operator denied a request — recorded as the verbose form.
	h.Record(req, types.Decision{
		Effect: types.EffectAskUserResolvedDeny,
		Source: types.SourceApprovalQueue,
	}, now)

	// TUI asks: was there an opposite-of-allow decision on this host?
	// Pre-fix: "ask_user_resolved_deny" != "allow" → true (correct by
	// coincidence, but for the wrong reason — the string comparison
	// would also flag "ask_user_resolved_allow" as opposite to "allow").
	// Post-fix: normalized to "deny" → correctly returns true.
	if !h.HasOppositeEffect("example.com", "allow") {
		t.Errorf("HasOppositeEffect should return true for a prior ask_user_resolved_deny vs current allow")
	}

	// Now the symmetric false-positive case: prior ask_user_resolved_allow
	// vs current allow. Same direction — should NOT be opposite.
	// Pre-fix: "ask_user_resolved_allow" != "allow" → returned true
	// (false positive). Post-fix: normalized to "allow" → matches,
	// not opposite, returns false (unless a deny is also in history).
	h2 := NewHistory(64)
	h2.Record(req, types.Decision{
		Effect: types.EffectAskUserResolvedAllow,
		Source: types.SourceApprovalQueue,
	}, now)
	if h2.HasOppositeEffect("example.com", "allow") {
		t.Errorf("HasOppositeEffect should return false for a prior ask_user_resolved_allow vs current allow (same direction)")
	}
}
