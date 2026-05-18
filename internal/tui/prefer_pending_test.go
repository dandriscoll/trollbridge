package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestDisplayedOps_PendingAtBottomOldestFirst pins #156's sort
// invariant: resolved ops at the top of the slice (preserving
// existing newest-UpdatedAt-first order), pending ops at the
// bottom sorted by StartedAt ascending — oldest at the top of
// pending, newest at the very bottom.
func TestDisplayedOps_PendingAtBottomOldestFirst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			opAt("done-1", "GET", "https://done.example/", "200", "", t0.Add(10*time.Second)),
		},
		Holds: []approvals.Snapshot{
			{ID: "hold-newest", Method: "POST", Scheme: "https", Host: "newer.example", Port: 443, Path: "/", CreatedAt: t0.Add(30 * time.Second)},
			{ID: "hold-oldest", Method: "POST", Scheme: "https", Host: "older.example", Port: 443, Path: "/", CreatedAt: t0.Add(5 * time.Second)},
			{ID: "hold-middle", Method: "POST", Scheme: "https", Host: "middle.example", Port: 443, Path: "/", CreatedAt: t0.Add(20 * time.Second)},
		},
	}
	d := DisplayedOps(m)
	if len(d) != 4 {
		t.Fatalf("displayed len = %d, want 4 (1 resolved + 3 pending)", len(d))
	}
	if d[0].Status != "200" {
		t.Errorf("row 0 should be the resolved op; got status %q", d[0].Status)
	}
	for i := 1; i < 4; i++ {
		if d[i].Status != opstream.StatusPending {
			t.Errorf("row %d should be pending; got status %q", i, d[i].Status)
		}
	}
	// Within pending: oldest-at-top, newest-at-bottom.
	wantOrder := []string{"hold-oldest", "hold-middle", "hold-newest"}
	for i, want := range wantOrder {
		if got := d[1+i].HoldID; got != want {
			t.Errorf("pending row %d HoldID = %q, want %q (full pending region: %+v)",
				i, got, want, []DisplayedOp{d[1], d[2], d[3]})
		}
	}
}

// TestApplyOpsTick_IdleSnapToNewestPending: with the cursor on a
// non-pending row, after idleSnapTicks ticks with no key events,
// the cursor snaps to the bottommost pending row.
func TestApplyOpsTick_IdleSnapToNewestPending(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	holds := []approvals.Snapshot{
		{ID: "hold-old", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", CreatedAt: t0},
		{ID: "hold-new", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", CreatedAt: t0.Add(time.Minute)},
	}
	m := Model{
		Ops: []opstream.Op{
			opAt("done", "GET", "https://done.example/", "200", "", t0.Add(2*time.Minute)),
		},
		Holds:    holds,
		Selected: 0, // resolved row
	}
	// Tick idleSnapTicks-1 times — cursor must NOT snap yet.
	for i := 0; i < idleSnapTicks-1; i++ {
		var cmd Cmd
		m, cmd = applyOpsTick(m, OpsTickResult{Ops: m.Ops})
		_ = cmd
	}
	if m.Selected != 0 {
		t.Fatalf("cursor moved before idle threshold reached; Selected = %d", m.Selected)
	}
	// One more tick crosses the threshold.
	m, _ = applyOpsTick(m, OpsTickResult{Ops: m.Ops})
	displayed := DisplayedOps(m)
	if m.Selected != len(displayed)-1 {
		t.Fatalf("cursor did not snap to bottommost row; Selected = %d, want %d", m.Selected, len(displayed)-1)
	}
	if displayed[m.Selected].HoldID != "hold-new" {
		t.Errorf("bottommost row should be the newest pending hold; got HoldID = %q", displayed[m.Selected].HoldID)
	}
}

// TestApplyOpsTick_IdleSnapNoOpWhenAlreadyOnPending pins
// rule 3: never move the cursor on the pending stack. With the
// cursor already on a pending row, idle ticks don't relocate it.
func TestApplyOpsTick_IdleSnapNoOpWhenAlreadyOnPending(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Holds: []approvals.Snapshot{
			{ID: "hold-old", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", CreatedAt: t0},
			{ID: "hold-new", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", CreatedAt: t0.Add(time.Minute)},
		},
	}
	// First, get the cursor onto the oldest pending row.
	displayed := DisplayedOps(m)
	for i := range displayed {
		if displayed[i].HoldID == "hold-old" {
			m.Selected = i
			break
		}
	}
	startSelected := m.Selected
	// Idle past the threshold.
	for i := 0; i <= idleSnapTicks; i++ {
		m, _ = applyOpsTick(m, OpsTickResult{Ops: nil})
	}
	if m.Selected != startSelected {
		t.Errorf("cursor moved while already on a pending row; Selected was %d, now %d", startSelected, m.Selected)
	}
}

// TestApplyOpsTick_IdleSnapNoOpWithoutPending: no pending rows means
// no snap. The counter still increments but stays unused.
func TestApplyOpsTick_IdleSnapNoOpWithoutPending(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			opAt("done", "GET", "https://done.example/", "200", "", t0),
		},
		Selected: 0,
	}
	for i := 0; i <= idleSnapTicks+2; i++ {
		m, _ = applyOpsTick(m, OpsTickResult{Ops: m.Ops})
	}
	if m.Selected != 0 {
		t.Errorf("cursor moved with no pending rows present; Selected = %d, want 0", m.Selected)
	}
}

// TestApplyKey_ResetsIdleCounter: any key event resets the idle
// counter so the cursor doesn't get yanked away from the operator's
// active navigation.
func TestApplyKey_ResetsIdleCounter(t *testing.T) {
	m := Model{LastInputTicks: idleSnapTicks - 1}
	m, _ = applyKey(m, KeyEvent{Rune: 'r'})
	if m.LastInputTicks != 0 {
		t.Errorf("applyKey did not reset LastInputTicks; got %d, want 0", m.LastInputTicks)
	}
}
