package tui

import "testing"

// TestSuspendKeyFromApprovals pins #176: `z` in the approvals pane asks
// the runtime to suspend (CmdSuspend), the signal-free half of the
// job-control feature. The SIGTSTP/SIGCONT round-trip itself needs a
// PTY harness and is exercised manually.
func TestSuspendKeyFromApprovals(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, Selected: -1}
	_, cmd := Apply(m, KeyEvent{Rune: 'z'})
	if _, ok := cmd.(CmdSuspend); !ok {
		t.Fatalf("z in approvals pane: got %T, want CmdSuspend", cmd)
	}
}

// TestSuspendKeyNotStolenFromConsole verifies `z` typed into the console
// is a literal character, not a suspend — the operator must be able to
// type words containing 'z' without backgrounding the process.
func TestSuspendKeyNotStolenFromConsole(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanelOpen: true,
		Console:         ConsoleModel{Prompt: "trollbridge> "},
	}
	_, cmd := Apply(m, KeyEvent{Rune: 'z'})
	if _, ok := cmd.(CmdSuspend); ok {
		t.Fatal("z in console pane was treated as suspend; should be literal input")
	}
}
