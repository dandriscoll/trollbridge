package approvals

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestQueue_DoubleApproveIsSafe pins the #53-driven safety:
// concurrent or back-to-back resolutions on the same hold cannot
// deadlock. The first resolver wins; subsequent ones return false
// because the cap-1 resolveCh is already full.
func TestQueue_DoubleApproveIsSafe(t *testing.T) {
	q := New(8, time.Second, "deny")
	defer q.Shutdown()
	_, _, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	id := q.Pending()[0].ID

	if !q.Approve(id, "once", "tui") {
		t.Fatal("first Approve returned false")
	}
	// Without a Wait drain, the resolveCh is full. A second Approve
	// would deadlock pre-fix; non-blocking send returns false safely.
	if q.Approve(id, "once", "tui") {
		t.Errorf("second Approve returned true while resolveCh still full (should be false)")
	}
	if q.Deny(id, "double", "tui") {
		t.Errorf("Deny after Approve returned true while resolveCh still full")
	}
}

// TestQueue_ConcurrentResolversFirstWins fires Approve and Deny on
// the same hold from two goroutines. Exactly one should win and Wait
// must observe exactly one decision (no deadlock, no leak).
func TestQueue_ConcurrentResolversFirstWins(t *testing.T) {
	q := New(8, time.Second, "deny")
	defer q.Shutdown()
	_, ch, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	id := q.Pending()[0].ID

	var approveOK, denyOK bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); approveOK = q.Approve(id, "once", "tui") }()
	go func() { defer wg.Done(); denyOK = q.Deny(id, "race", "tui") }()
	wg.Wait()

	if approveOK == denyOK {
		t.Errorf("expected exactly one of Approve/Deny to succeed; approveOK=%v denyOK=%v", approveOK, denyOK)
	}
	d := q.Wait(context.Background(), id, ch)
	if d.Effect == "" {
		t.Errorf("Wait observed empty Decision after race")
	}
}

// TestQueue_ResolveByAdvisorWinsRace pins the new advisor path: when
// the advisor pushes a confident decision before the operator,
// Wait sees the advisor's Decision (with SourceLLMAdvisor preserved).
func TestQueue_ResolveByAdvisorWinsRace(t *testing.T) {
	q := New(8, time.Second, "deny")
	defer q.Shutdown()
	_, ch, err := q.Enqueue(newReq(), types.Decision{Effect: types.EffectAskUser})
	if err != nil {
		t.Fatal(err)
	}
	id := q.Pending()[0].ID

	advisorDecision := types.Decision{
		Effect:    types.EffectAllow,
		Source:    types.SourceLLMAdvisor,
		AdvisorID: "test-advisor",
		Reason:    "advisor confident allow",
	}
	if !q.ResolveByAdvisor(id, advisorDecision) {
		t.Fatal("ResolveByAdvisor returned false on first call")
	}
	d := q.Wait(context.Background(), id, ch)
	if d.Effect != types.EffectAllow {
		t.Errorf("Wait Effect = %q, want %q", d.Effect, types.EffectAllow)
	}
	if d.Source != types.SourceLLMAdvisor {
		t.Errorf("Wait Source = %q, want %q (advisor attribution preserved)", d.Source, types.SourceLLMAdvisor)
	}
	if d.AdvisorID != "test-advisor" {
		t.Errorf("Wait AdvisorID = %q, want test-advisor", d.AdvisorID)
	}
	// Subsequent operator action no-ops.
	if q.Approve(id, "once", "tui") {
		t.Errorf("Approve after ResolveByAdvisor returned true")
	}
}
