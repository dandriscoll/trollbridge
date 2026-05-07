package tui

import (
	"errors"
	"testing"

	"github.com/dandriscoll/drawbridge/internal/approvals"
)

func snap(id, host string) approvals.Snapshot {
	return approvals.Snapshot{ID: id, Host: host, Port: 443}
}

func TestApply_TickPopulatesHoldsAndClearsError(t *testing.T) {
	m := Model{LastErr: "stale"}
	got, _ := Apply(m, TickResult{Holds: []approvals.Snapshot{snap("a", "x")}})
	if len(got.Holds) != 1 || got.Holds[0].ID != "a" {
		t.Errorf("Holds = %+v, want one with id=a", got.Holds)
	}
	if got.LastErr != "" {
		t.Errorf("LastErr = %q, want cleared", got.LastErr)
	}
	if got.Selected != 0 {
		t.Errorf("Selected = %d, want 0", got.Selected)
	}
}

func TestApply_TickEmptyClampsSelectionToMinusOne(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x")}, Selected: 0}
	got, _ := Apply(m, TickResult{Holds: nil})
	if got.Selected != -1 {
		t.Errorf("Selected = %d, want -1 on empty", got.Selected)
	}
}

func TestApply_TickShrunkClampsSelection(t *testing.T) {
	m := Model{
		Holds:    []approvals.Snapshot{snap("a", "x"), snap("b", "y"), snap("c", "z")},
		Selected: 2,
	}
	got, _ := Apply(m, TickResult{Holds: []approvals.Snapshot{snap("a", "x")}})
	if got.Selected != 0 {
		t.Errorf("Selected = %d, want 0 after shrink", got.Selected)
	}
}

func TestApply_TickErrorSetsFooterPreservesHolds(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x")}, Selected: 0}
	got, _ := Apply(m, TickResult{Err: errors.New("connection refused")})
	if !contains(got.LastErr, "connection refused") {
		t.Errorf("LastErr = %q, want it to contain the err message", got.LastErr)
	}
	if len(got.Holds) != 1 {
		t.Errorf("Holds = %+v, want preserved on error", got.Holds)
	}
}

func TestApply_KeyApproveOnSelected(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x"), snap("b", "y")}, Selected: 1}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	approve, ok := cmd.(CmdApprove)
	if !ok {
		t.Fatalf("cmd = %T, want CmdApprove", cmd)
	}
	if approve.ID != "b" {
		t.Errorf("CmdApprove.ID = %q, want b", approve.ID)
	}
	if !contains(got.LastInfo, "b") {
		t.Errorf("LastInfo = %q, want it to mention id=b", got.LastInfo)
	}
}

func TestApply_KeyDenyOnSelected(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x")}, Selected: 0}
	_, cmd := Apply(m, KeyEvent{Rune: 'd'})
	deny, ok := cmd.(CmdDeny)
	if !ok {
		t.Fatalf("cmd = %T, want CmdDeny", cmd)
	}
	if deny.ID != "a" {
		t.Errorf("CmdDeny.ID = %q, want a", deny.ID)
	}
}

func TestApply_KeyApproveWhenEmptyShowsError(t *testing.T) {
	m := Model{Holds: nil, Selected: -1}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	if _, ok := cmd.(CmdNone); !ok {
		t.Fatalf("cmd = %T, want CmdNone", cmd)
	}
	if got.LastErr == "" {
		t.Errorf("LastErr empty; want a hint about no hold selected")
	}
}

func TestApply_KeyMovementClamps(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x"), snap("b", "y")}, Selected: 0}
	// up at top stays at 0
	got, _ := Apply(m, KeyEvent{Key: KeyUp})
	if got.Selected != 0 {
		t.Errorf("Up at top: Selected = %d, want 0", got.Selected)
	}
	// down moves to 1
	got, _ = Apply(got, KeyEvent{Key: KeyDown})
	if got.Selected != 1 {
		t.Errorf("Down: Selected = %d, want 1", got.Selected)
	}
	// down at bottom stays at 1
	got, _ = Apply(got, KeyEvent{Key: KeyDown})
	if got.Selected != 1 {
		t.Errorf("Down at bottom: Selected = %d, want 1", got.Selected)
	}
	// k = up alias
	got, _ = Apply(got, KeyEvent{Rune: 'k'})
	if got.Selected != 0 {
		t.Errorf("k: Selected = %d, want 0", got.Selected)
	}
	// j = down alias
	got, _ = Apply(got, KeyEvent{Rune: 'j'})
	if got.Selected != 1 {
		t.Errorf("j: Selected = %d, want 1", got.Selected)
	}
}

func TestApply_KeyQuit(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   KeyEvent
	}{
		{"q", KeyEvent{Rune: 'q'}},
		{"esc", KeyEvent{Key: KeyEsc}},
		{"ctrl-c", KeyEvent{Key: KeyCtrlC}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{}
			got, cmd := Apply(m, tc.ev)
			if _, ok := cmd.(CmdQuit); !ok {
				t.Errorf("cmd = %T, want CmdQuit", cmd)
			}
			if !got.Quit {
				t.Errorf("Quit not set on model")
			}
		})
	}
}

func TestApply_KeyRefresh(t *testing.T) {
	_, cmd := Apply(Model{}, KeyEvent{Rune: 'r'})
	if _, ok := cmd.(CmdRefresh); !ok {
		t.Errorf("cmd = %T, want CmdRefresh", cmd)
	}
}

func TestApply_ActionResultSuccessRemovesHold(t *testing.T) {
	m := Model{
		Holds:    []approvals.Snapshot{snap("a", "x"), snap("b", "y"), snap("c", "z")},
		Selected: 1,
	}
	got, cmd := Apply(m, ActionResult{ID: "b", Action: "approve"})
	if len(got.Holds) != 2 {
		t.Errorf("Holds len = %d, want 2 after removing b", len(got.Holds))
	}
	for _, h := range got.Holds {
		if h.ID == "b" {
			t.Errorf("hold b still present: %+v", got.Holds)
		}
	}
	if !contains(got.LastInfo, "approve") {
		t.Errorf("LastInfo = %q, want it to mention approve", got.LastInfo)
	}
	if _, ok := cmd.(CmdRefresh); !ok {
		t.Errorf("cmd = %T, want CmdRefresh on success (forces authoritative re-fetch)", cmd)
	}
}

func TestApply_ActionResultFailureSetsError(t *testing.T) {
	m := Model{
		Holds:    []approvals.Snapshot{snap("a", "x")},
		Selected: 0,
		LastInfo: "approving a…",
	}
	got, _ := Apply(m, ActionResult{ID: "a", Action: "approve", Err: errors.New("boom")})
	if !contains(got.LastErr, "boom") {
		t.Errorf("LastErr = %q, want it to contain the err", got.LastErr)
	}
	if got.LastInfo != "" {
		t.Errorf("LastInfo = %q, want cleared on error", got.LastInfo)
	}
	if len(got.Holds) != 1 {
		t.Errorf("Holds modified despite failure: %+v", got.Holds)
	}
}

func TestApply_Resize(t *testing.T) {
	got, cmd := Apply(Model{}, ResizeEvent{Cols: 80, Rows: 24})
	if got.Cols != 80 || got.Rows != 24 {
		t.Errorf("dims = %dx%d, want 80x24", got.Cols, got.Rows)
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone on resize", cmd)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || (len(needle) > 0 && indexOf(haystack, needle) >= 0))
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
