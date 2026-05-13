package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/approvals"
)

func snap(id, host string) approvals.Snapshot {
	return approvals.Snapshot{ID: id, Host: host, Port: 443}
}

// TestApply_TickPreservesSelectionByID closes the second half of
// the #39 fix: when a tick replaces the holds slice in a different
// order, Selected must follow the same hold by ID rather than
// stay pinned to a stale index.
//
// De-tautologized per #104: place the target at a different index
// pre vs post-mutation. The earlier version had b at index 1 in
// both pre and post slices, which let "Selected stays at 1" pass
// the test even without ID tracking.
func TestApply_TickPreservesSelectionByID(t *testing.T) {
	a, b, c := snap("a", "h1"), snap("b", "h2"), snap("c", "h3")
	m := Model{Holds: []approvals.Snapshot{a, b, c}, Selected: 1} // selecting b
	// New order [b, a, c]: b moves to index 0. The fix tracks by ID,
	// so Selected must follow b to index 0 — not stay at index 1
	// (which would now point at a, the wrong hold).
	got, _ := Apply(m, TickResult{Holds: []approvals.Snapshot{b, a, c}})
	if got.Selected != 0 {
		t.Fatalf("Selected = %d, want 0 (hold b's new index)", got.Selected)
	}
	if got.Holds[got.Selected].ID != "b" {
		t.Errorf("hold at Selected = %s, want b", got.Holds[got.Selected].ID)
	}
}

// TestApply_TickResolvedHoldDropsSelection covers the case where
// the previously-selected hold has been resolved by another
// channel (operator pressed approve elsewhere, advisor resolved):
// Selected falls through to clampSelection and lands on a sane
// neighbor rather than dangling.
func TestApply_TickResolvedHoldDropsSelection(t *testing.T) {
	a, b, c := snap("a", "h1"), snap("b", "h2"), snap("c", "h3")
	m := Model{Holds: []approvals.Snapshot{a, b, c}, Selected: 1} // selecting b
	// b has resolved; tick brings only a and c.
	got, _ := Apply(m, TickResult{Holds: []approvals.Snapshot{a, c}})
	if got.Selected < 0 || got.Selected >= len(got.Holds) {
		t.Fatalf("Selected = %d out of range for %d holds", got.Selected, len(got.Holds))
	}
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
	if !strings.Contains(got.LastErr, "connection refused") {
		t.Errorf("LastErr = %q, want it to contain the err message", got.LastErr)
	}
	if len(got.Holds) != 1 {
		t.Errorf("Holds = %+v, want preserved on error", got.Holds)
	}
}

// Approvals-pane-focused key tests.

func TestApply_KeyApproveOnSelected(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x"), snap("b", "y")}, Selected: 1, Focused: PaneApprovals}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	approve, ok := cmd.(CmdApprove)
	if !ok {
		t.Fatalf("cmd = %T, want CmdApprove", cmd)
	}
	if approve.ID != "b" {
		t.Errorf("CmdApprove.ID = %q, want b", approve.ID)
	}
	// Status message names the URL, not the hold id (#92). snap("b","y")
	// produces an op with Host "y" — the URL ends with "y".
	if !strings.Contains(got.LastInfo, "y") {
		t.Errorf("LastInfo = %q, want it to mention URL host=y", got.LastInfo)
	}
}

func TestApply_KeyDenyOnSelected(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x")}, Selected: 0, Focused: PaneApprovals}
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
	m := Model{Holds: nil, Selected: -1, Focused: PaneApprovals}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	if _, ok := cmd.(CmdNone); !ok {
		t.Fatalf("cmd = %T, want CmdNone", cmd)
	}
	if got.LastErr == "" {
		t.Errorf("LastErr empty; want a hint about no hold selected")
	}
}

func TestApply_KeyMovementClamps(t *testing.T) {
	m := Model{Holds: []approvals.Snapshot{snap("a", "x"), snap("b", "y")}, Selected: 0, Focused: PaneApprovals}
	got, _ := Apply(m, KeyEvent{Key: KeyUp})
	if got.Selected != 0 {
		t.Errorf("Up at top: Selected = %d, want 0", got.Selected)
	}
	got, _ = Apply(got, KeyEvent{Key: KeyDown})
	if got.Selected != 1 {
		t.Errorf("Down: Selected = %d, want 1", got.Selected)
	}
	got, _ = Apply(got, KeyEvent{Key: KeyDown})
	if got.Selected != 1 {
		t.Errorf("Down at bottom: Selected = %d, want 1", got.Selected)
	}
	got, _ = Apply(got, KeyEvent{Rune: 'k'})
	if got.Selected != 0 {
		t.Errorf("k: Selected = %d, want 0", got.Selected)
	}
	got, _ = Apply(got, KeyEvent{Rune: 'j'})
	if got.Selected != 1 {
		t.Errorf("j: Selected = %d, want 1", got.Selected)
	}
}

func TestApply_KeyQuit_ApprovalsPane(t *testing.T) {
	// Quit affordances: 'q' from approvals focus, Ctrl-C from any
	// state. Esc no longer quits (#87 — Esc closes the bottom panel
	// when one is open, otherwise is a no-op).
	for _, tc := range []struct {
		name string
		ev   KeyEvent
	}{
		{"q", KeyEvent{Rune: 'q'}},
		{"ctrl-c", KeyEvent{Key: KeyCtrlC}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{Focused: PaneApprovals}
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

func TestApply_KeyRefresh_ApprovalsPane(t *testing.T) {
	_, cmd := Apply(Model{Focused: PaneApprovals}, KeyEvent{Rune: 'r'})
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
	if !strings.Contains(got.LastInfo, "approve") {
		t.Errorf("LastInfo = %q, want it to mention approve", got.LastInfo)
	}
	if _, ok := cmd.(CmdRefresh); !ok {
		t.Errorf("cmd = %T, want CmdRefresh on success", cmd)
	}
}

func TestApply_ActionResultFailureSetsError(t *testing.T) {
	m := Model{
		Holds:    []approvals.Snapshot{snap("a", "x")},
		Selected: 0,
		LastInfo: "approving a…",
	}
	got, _ := Apply(m, ActionResult{ID: "a", Action: "approve", Err: errors.New("boom")})
	if !strings.Contains(got.LastErr, "boom") {
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

// Tab switches focus between panes.

func TestApply_TabTogglesFocus(t *testing.T) {
	// Tab only toggles when there is a bottom pane to focus on (#66).
	m := Model{Focused: PaneApprovals, BottomPanelOpen: true}
	got, cmd := Apply(m, KeyEvent{Key: KeyTab})
	if got.Focused != PaneConsole {
		t.Errorf("after first Tab, Focused = %v, want PaneConsole", got.Focused)
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone on Tab", cmd)
	}
	got, _ = Apply(got, KeyEvent{Key: KeyTab})
	if got.Focused != PaneApprovals {
		t.Errorf("after second Tab, Focused = %v, want PaneApprovals", got.Focused)
	}
}

// Ctrl-C is global — quits regardless of focus.

func TestApply_CtrlCQuitsFromConsolePane(t *testing.T) {
	m := Model{Focused: PaneConsole}
	got, cmd := Apply(m, KeyEvent{Key: KeyCtrlC})
	if _, ok := cmd.(CmdQuit); !ok {
		t.Errorf("cmd = %T, want CmdQuit", cmd)
	}
	if !got.Quit {
		t.Errorf("Quit not set")
	}
}

// 'q' in the console pane is just a letter.

func TestApply_QInConsolePaneAppendsToInput(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Prompt: "> "}}
	got, cmd := Apply(m, KeyEvent{Rune: 'q'})
	if got.Quit {
		t.Errorf("Quit set on q-in-console; should be a literal")
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone", cmd)
	}
	if string(got.Console.Input) != "q" {
		t.Errorf("Console.Input = %q, want %q", string(got.Console.Input), "q")
	}
	if got.Console.Cursor != 1 {
		t.Errorf("Console.Cursor = %d, want 1", got.Console.Cursor)
	}
}

// Under #87, Esc closes any open bottom panel and returns focus to
// approvals (without quitting). When no panel is open, Esc is a
// no-op.

func TestApply_EscInConsolePaneClosesPanelAndReturnsFocus(t *testing.T) {
	m := Model{
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelConsole,
		BottomPanelOpen: true,
	}
	got, cmd := Apply(m, KeyEvent{Key: KeyEsc})
	if got.Quit {
		t.Errorf("Esc-in-console set Quit; should only close panel")
	}
	if got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen still true after Esc")
	}
	if got.Focused != PaneApprovals {
		t.Errorf("Focused = %v, want PaneApprovals after Esc", got.Focused)
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone", cmd)
	}
}

// Console-pane editing: backspace, Ctrl-U.

func TestApply_BackspaceDeletesPrev(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Input: []rune("hello"), Cursor: 5, Prompt: "> "}}
	got, _ := Apply(m, KeyEvent{Key: KeyBackspace})
	if string(got.Console.Input) != "hell" {
		t.Errorf("Input = %q, want %q", string(got.Console.Input), "hell")
	}
	if got.Console.Cursor != 4 {
		t.Errorf("Cursor = %d, want 4", got.Console.Cursor)
	}
}

func TestApply_BackspaceOnEmptyIsNoOp(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Prompt: "> "}}
	got, _ := Apply(m, KeyEvent{Key: KeyBackspace})
	if len(got.Console.Input) != 0 || got.Console.Cursor != 0 {
		t.Errorf("backspace on empty produced state %+v", got.Console)
	}
}

func TestApply_CtrlUKillsLine(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Input: []rune("foo bar"), Cursor: 7, Prompt: "> "}}
	got, _ := Apply(m, KeyEvent{Key: KeyCtrlU})
	if len(got.Console.Input) != 0 || got.Console.Cursor != 0 {
		t.Errorf("Ctrl-U did not clear line: %+v", got.Console)
	}
}

// Enter in the console pane requests a CmdConsoleExec and echoes
// the prompt+input into scrollback.

func TestApply_EnterRequestsConsoleExec(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Input: []rune("allow x.example"), Cursor: 15, Prompt: "trollbridge> "}}
	got, cmd := Apply(m, KeyEvent{Key: KeyEnter})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	if exec.Line != "allow x.example" {
		t.Errorf("CmdConsoleExec.Line = %q, want %q", exec.Line, "allow x.example")
	}
	if len(got.Console.Input) != 0 || got.Console.Cursor != 0 {
		t.Errorf("input not reset after Enter: %+v", got.Console)
	}
	if len(got.Console.Scrollback) == 0 {
		t.Fatal("scrollback empty after Enter; want echoed line")
	}
	last := got.Console.Scrollback[len(got.Console.Scrollback)-1]
	if !strings.Contains(last, "allow x.example") {
		t.Errorf("scrollback echo = %q, want it to include the input", last)
	}
}

func TestApply_EnterOnEmptyLineDoesNotExec(t *testing.T) {
	m := Model{Focused: PaneConsole, Console: ConsoleModel{Prompt: "> "}}
	_, cmd := Apply(m, KeyEvent{Key: KeyEnter})
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T on empty Enter, want CmdNone", cmd)
	}
}

// Console exec result appends output and (when asked) quits.

func TestApply_ConsoleExecResultAppendsOutput(t *testing.T) {
	m := Model{Console: ConsoleModel{Prompt: "> "}}
	got, _ := Apply(m, ConsoleExecResult{Output: "line one\nline two\n"})
	if len(got.Console.Scrollback) != 2 {
		t.Fatalf("scrollback len = %d, want 2", len(got.Console.Scrollback))
	}
	if got.Console.Scrollback[0] != "line one" || got.Console.Scrollback[1] != "line two" {
		t.Errorf("scrollback = %v", got.Console.Scrollback)
	}
}

func TestApply_ConsoleExecResultQuitSetsModelQuit(t *testing.T) {
	m := Model{Console: ConsoleModel{Prompt: "> "}}
	got, cmd := Apply(m, ConsoleExecResult{Output: "", Quit: true})
	if !got.Quit {
		t.Errorf("Quit not set on model")
	}
	if _, ok := cmd.(CmdQuit); !ok {
		t.Errorf("cmd = %T, want CmdQuit", cmd)
	}
}

// Scrollback caps.

func TestApply_ScrollbackCaps(t *testing.T) {
	m := Model{Console: ConsoleModel{Prompt: "> "}}
	for i := 0; i < maxScrollback+50; i++ {
		m.Console = appendScrollback(m.Console, "line")
	}
	if len(m.Console.Scrollback) != maxScrollback {
		t.Errorf("scrollback len = %d, want %d", len(m.Console.Scrollback), maxScrollback)
	}
}
