package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyKeyApprovals_NavSetsPause pins that j/k/Up/Down each
// arm the OpsPausedTicks counter (#89).
func TestApplyKeyApprovals_NavSetsPause(t *testing.T) {
	ops := []opstream.Op{
		{RequestID: "a", Method: "GET", URL: "https://x/", UpdatedAt: time.Now()},
		{RequestID: "b", Method: "GET", URL: "https://y/", UpdatedAt: time.Now()},
	}
	for _, ev := range []KeyEvent{
		{Rune: 'j'}, {Rune: 'k'}, {Key: KeyDown}, {Key: KeyUp},
	} {
		m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, Ops: ops}
		got, _ := Apply(m, ev)
		if got.OpsPausedTicks != opsPauseTicks {
			t.Errorf("ev=%+v: OpsPausedTicks = %d, want %d", ev, got.OpsPausedTicks, opsPauseTicks)
		}
	}
}

// TestApplyOpsTick_HonorsPause pins that an OpsTickResult arriving
// while OpsPausedTicks > 0 does not replace m.Ops, and decrements
// the counter.
func TestApplyOpsTick_HonorsPause(t *testing.T) {
	oldOps := []opstream.Op{{RequestID: "old", URL: "https://old/"}}
	newOps := []opstream.Op{{RequestID: "new", URL: "https://new/"}}
	m := Model{Ops: oldOps, OpsPausedTicks: 2}
	got, _ := Apply(m, OpsTickResult{Ops: newOps})
	if len(got.Ops) != 1 || got.Ops[0].RequestID != "old" {
		t.Errorf("paused tick replaced m.Ops: %+v", got.Ops)
	}
	if got.OpsPausedTicks != 1 {
		t.Errorf("OpsPausedTicks = %d, want 1", got.OpsPausedTicks)
	}
}

// TestApplyOpsTick_ResumesWhenCounterZero verifies normal ingestion
// resumes once the counter hits zero.
func TestApplyOpsTick_ResumesWhenCounterZero(t *testing.T) {
	oldOps := []opstream.Op{{RequestID: "old", URL: "https://old/"}}
	newOps := []opstream.Op{{RequestID: "new", URL: "https://new/"}}
	m := Model{Ops: oldOps, OpsPausedTicks: 0}
	got, _ := Apply(m, OpsTickResult{Ops: newOps})
	if len(got.Ops) != 1 || got.Ops[0].RequestID != "new" {
		t.Errorf("unpaused tick did not replace m.Ops: %+v", got.Ops)
	}
}

// TestApplyTick_HonorsPause pins the same contract on the holds
// tick — both feed the displayed list and both must respect pause.
func TestApplyTick_HonorsPause(t *testing.T) {
	oldHolds := []approvals.Snapshot{{ID: "old"}}
	newHolds := []approvals.Snapshot{{ID: "new"}}
	m := Model{Holds: oldHolds, OpsPausedTicks: 1}
	got, _ := Apply(m, TickResult{Holds: newHolds})
	if len(got.Holds) != 1 || got.Holds[0].ID != "old" {
		t.Errorf("paused holds tick replaced m.Holds: %+v", got.Holds)
	}
	if got.OpsPausedTicks != 0 {
		t.Errorf("OpsPausedTicks = %d, want 0 after decrement", got.OpsPausedTicks)
	}
}

// TestApplyKey_TabClearsPause pins that Tab focus-shift releases
// the nav-pause immediately (#89).
func TestApplyKey_TabClearsPause(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneApprovals,
		BottomPanelOpen: true,
		OpsPausedTicks:  2,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyTab})
	if got.OpsPausedTicks != 0 {
		t.Errorf("Tab did not clear OpsPausedTicks; got %d", got.OpsPausedTicks)
	}
}

// TestApplyKey_DigitClearsPause pins that explicit panel-switch
// keystrokes (0/1/2/3/4) release the nav-pause.
func TestApplyKey_DigitClearsPause(t *testing.T) {
	for _, r := range []rune{'0', '1', '2', '3', '4'} {
		m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, OpsPausedTicks: 2}
		got, _ := Apply(m, KeyEvent{Rune: r})
		if got.OpsPausedTicks != 0 {
			t.Errorf("digit %q did not clear OpsPausedTicks; got %d", r, got.OpsPausedTicks)
		}
	}
}

// TestApplyKeyApprovals_RefreshDoesNotSetPause verifies the explicit
// 'r' refresh ingests fresh data — operator asked for it.
func TestApplyKeyApprovals_RefreshDoesNotSetPause(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	got, _ := Apply(m, KeyEvent{Rune: 'r'})
	if got.OpsPausedTicks != 0 {
		t.Errorf("'r' incorrectly set OpsPausedTicks; got %d", got.OpsPausedTicks)
	}
}

// TestApplyOpsTick_CursorFollowsSelectedRequestIDAfterResort pins
// the "cursor stays on the present line" contract (#89 part 2): a
// re-sorted ops slice keeps Selected on the same logical request.
func TestApplyOpsTick_CursorFollowsSelectedRequestIDAfterResort(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	oldOps := []opstream.Op{
		{RequestID: "a", Method: "GET", URL: "https://a/", UpdatedAt: t0.Add(2 * time.Second)},
		{RequestID: "b", Method: "GET", URL: "https://b/", UpdatedAt: t0.Add(1 * time.Second)},
		{RequestID: "c", Method: "GET", URL: "https://c/", UpdatedAt: t0},
	}
	// Operator selects request b (index 1 in newest-first order).
	m := Model{Ops: oldOps, Selected: 1}
	// New tick: 'c' became newest; ordering is c, a, b.
	newOps := []opstream.Op{
		{RequestID: "c", Method: "GET", URL: "https://c/", UpdatedAt: t0.Add(10 * time.Second)},
		{RequestID: "a", Method: "GET", URL: "https://a/", UpdatedAt: t0.Add(2 * time.Second)},
		{RequestID: "b", Method: "GET", URL: "https://b/", UpdatedAt: t0.Add(1 * time.Second)},
	}
	got, _ := Apply(m, OpsTickResult{Ops: newOps})
	displayed := DisplayedOps(got)
	if got.Selected < 0 || got.Selected >= len(displayed) {
		t.Fatalf("Selected out of range: %d, len=%d", got.Selected, len(displayed))
	}
	if displayed[got.Selected].RequestID != "b" {
		t.Errorf("cursor moved off request b; now on %s", displayed[got.Selected].RequestID)
	}
}
