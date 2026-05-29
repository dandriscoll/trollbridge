package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyOpsTick_StickyPending_BurstDrainThenNewArrival is the
// load-bearing test for #191's reopen: when the cursor is on
// pending and a burst resolves ALL pending in one tick, the
// previous #191 fix's fall-through finds no pending to snap to,
// so the cursor lands on resolved. On the very next tick, a new
// pending arrives. Pre-fix: cursor stays on resolved for
// ~idleSnapTicks before snap (~6s window the user sees as
// "cursor doesn't stay on pending"). Post-fix: the sticky
// CursorPreferPending flag survives the drain and snaps the
// cursor to the new pending immediately.
//
// Fixture: 2 synth pending holds, cursor on the bottommost.
// Tick 1 (burst-drain): both resolve in one ops tick. No
// pending remains. Cursor falls to resolved (legacy behavior;
// invariant vacuous at this instant). Sticky flag is set.
// Tick 2 (new arrival): a fresh pending hold arrives. Sticky
// flag fires the snap-back. Cursor on the new pending.
func TestApplyOpsTick_StickyPending_BurstDrainThenNewArrival(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	holdA := approvals.Snapshot{ID: "A", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", CreatedAt: t0.Add(1 * time.Second)}
	holdB := approvals.Snapshot{ID: "B", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", CreatedAt: t0.Add(2 * time.Second)}
	m := Model{Holds: []approvals.Snapshot{holdA, holdB}}
	pre := DisplayedOps(m)
	// Cursor on the bottommost pending (newest).
	m.Selected = len(pre) - 1
	if pre[m.Selected].Status != opstream.StatusPending {
		t.Fatalf("setup: bottommost row should be pending; status=%q", pre[m.Selected].Status)
	}

	// Tick 1: burst drain. Both A and B resolve in one ops tick.
	// m.Holds is updated by an applyTick that races ahead; in this
	// test we run applyTick first (clears holds) then applyOpsTick.
	resolvedA := opstream.Op{
		RequestID: "req-A", Method: "GET", URL: "https://a.example/",
		Status: "200", StartedAt: holdA.CreatedAt, UpdatedAt: holdA.CreatedAt,
	}
	resolvedB := opstream.Op{
		RequestID: "req-B", Method: "GET", URL: "https://b.example/",
		Status: "200", StartedAt: holdB.CreatedAt, UpdatedAt: holdB.CreatedAt,
	}
	m, _ = applyTick(m, TickResult{Holds: nil})
	m, _ = applyOpsTick(m, OpsTickResult{Ops: []opstream.Op{resolvedA, resolvedB}})

	// At this instant no pending remains; cursor is on resolved.
	// Acceptable: invariant vacuous. But the sticky flag should
	// have been recorded.
	drainPost := DisplayedOps(m)
	if m.Selected >= 0 && m.Selected < len(drainPost) && !opIsResolved(drainPost[m.Selected].Status) {
		t.Logf("(diagnostic) cursor still on pending after burst — sticky flag not needed for this fixture")
	}

	// Tick 2: a new pending arrives. Cursor should snap to it.
	holdC := approvals.Snapshot{ID: "C", Method: "GET", Scheme: "https", Host: "c.example", Port: 443, Path: "/", CreatedAt: t0.Add(5 * time.Second)}
	m, _ = applyTick(m, TickResult{Holds: []approvals.Snapshot{holdC}})

	finalDisplayed := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(finalDisplayed) {
		t.Fatalf("post-arrival Selected = %d out of range for %d rows", m.Selected, len(finalDisplayed))
	}
	sel := finalDisplayed[m.Selected]
	if opIsResolved(sel.Status) {
		t.Errorf("after burst-drain + new pending arrival: cursor still on resolved row "+
			"(sticky-pending flag did not fire). Selected=%d HoldID=%q ReqID=%q status=%q. Full: %+v",
			m.Selected, sel.HoldID, sel.RequestID, sel.Status, finalDisplayed)
	}
	if sel.HoldID != "C" {
		t.Errorf("after new pending arrival: cursor should snap to new pending C; got HoldID=%q", sel.HoldID)
	}
}

// TestApplyOpsTick_StickyPending_ClearedOnUpArrow pins that the
// sticky flag is cleared when the user explicitly navigates Up
// off pending. After Up, a drain-then-arrival sequence should
// NOT snap back — Up was the operator's "leave pending" signal.
func TestApplyOpsTick_StickyPending_ClearedOnUpArrow(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	// One resolved + one pending. Cursor starts on pending.
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "req-X", Method: "GET", URL: "https://x.example/", Status: "200", StartedAt: t0, UpdatedAt: t0},
		},
		Holds: []approvals.Snapshot{
			{ID: "A", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", CreatedAt: t0.Add(1 * time.Second)},
		},
	}
	pre := DisplayedOps(m)
	for i := range pre {
		if pre[i].HoldID == "A" {
			m.Selected = i
			break
		}
	}
	// Two ticks of "stable" state so the sticky flag is firmly set.
	m, _ = applyTick(m, TickResult{Holds: m.Holds})
	m, _ = applyOpsTick(m, OpsTickResult{Ops: m.Ops})

	// User presses Up. Cursor moves to resolved row.
	m, _ = Apply(m, KeyEvent{Key: KeyUp})
	post := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(post) || !opIsResolved(post[m.Selected].Status) {
		t.Fatalf("after Up: expected cursor on resolved, got Selected=%d (%+v)", m.Selected, post)
	}

	// Drain pending, add new pending — sticky should NOT fire.
	m, _ = applyTick(m, TickResult{Holds: []approvals.Snapshot{
		{ID: "B", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", CreatedAt: t0.Add(5 * time.Second)},
	}})

	final := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(final) {
		t.Fatalf("final Selected = %d out of range", m.Selected)
	}
	if !opIsResolved(final[m.Selected].Status) {
		t.Errorf("after Up + new pending arrival: cursor moved to pending without operator request. "+
			"Up should disable the sticky-pending preference. Selected=%d status=%q",
			m.Selected, final[m.Selected].Status)
	}
}
