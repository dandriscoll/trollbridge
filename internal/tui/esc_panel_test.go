package tui

import (
	"testing"
)

// TestApplyKey_EscClosesOpenBottomPanelFromApprovalsFocus pins #87:
// Esc with the bottom panel open closes it without quitting.
func TestApplyKey_EscClosesOpenBottomPanelFromApprovalsFocus(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneApprovals,
		BottomPanel:     BottomPanelConsole,
		BottomPanelOpen: true,
	}
	got, cmd := Apply(m, KeyEvent{Key: KeyEsc})
	if got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen still true after Esc")
	}
	if got.Quit {
		t.Errorf("Quit set after Esc; #87 forbids it")
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone (no quit cmd)", cmd)
	}
}

// TestApplyKey_EscClosesOpenBottomPanelFromConsoleFocus verifies
// the same behavior when the operator had focus on the bottom pane.
// The console pane was previously the only place where Esc defocused
// without quitting; the new semantics make Esc close the panel
// from any focus.
func TestApplyKey_EscClosesOpenBottomPanelFromConsoleFocus(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelConsole,
		BottomPanelOpen: true,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen still true after Esc")
	}
	if got.Focused != PaneApprovals {
		t.Errorf("Focused = %d, want PaneApprovals", got.Focused)
	}
	if got.Quit {
		t.Errorf("Quit set after Esc; #87 forbids it")
	}
}

// TestApplyKey_EscClosesLLMPanelEvenWhenExpanded pins that Esc from
// the LLM modal/expanded view closes the panel entirely — Enter is
// the verb for collapse-but-keep-open.
func TestApplyKey_EscClosesLLMPanelEvenWhenExpanded(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelLLM,
		BottomPanelOpen: true,
		DigestExpanded:  true,
		DigestSelected:  "abc",
	}
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen still true; Esc should close the LLM panel")
	}
	if got.DigestExpanded {
		t.Errorf("DigestExpanded still true after Esc")
	}
}

// TestApplyKey_EscWithNoPanelIsNoOpAndDoesNotQuit pins the
// approvals-only path: Esc is silent, no Quit.
func TestApplyKey_EscWithNoPanelIsNoOpAndDoesNotQuit(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	got, cmd := Apply(m, KeyEvent{Key: KeyEsc})
	if got.Quit {
		t.Errorf("Quit set; #87 forbids Esc from quitting")
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone", cmd)
	}
}

// TestApplyKey_QStillQuitsFromApprovals verifies that the
// documented quit affordance is unchanged.
func TestApplyKey_QStillQuitsFromApprovals(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	got, cmd := Apply(m, KeyEvent{Rune: 'q'})
	if !got.Quit {
		t.Errorf("Quit not set after 'q'")
	}
	if _, ok := cmd.(CmdQuit); !ok {
		t.Errorf("cmd = %T, want CmdQuit", cmd)
	}
}

// TestApplyKey_CtrlCStillQuitsAlways verifies the global quit.
func TestApplyKey_CtrlCStillQuitsAlways(t *testing.T) {
	for _, focus := range []Pane{PaneApprovals, PaneConsole} {
		m := Model{Cols: 100, Rows: 30, Focused: focus, BottomPanelOpen: true}
		got, cmd := Apply(m, KeyEvent{Key: KeyCtrlC})
		if !got.Quit {
			t.Errorf("focus=%d: Quit not set after Ctrl-C", focus)
		}
		if _, ok := cmd.(CmdQuit); !ok {
			t.Errorf("focus=%d: cmd = %T, want CmdQuit", focus, cmd)
		}
	}
}

// (The GeneralizeOffer Esc-dismissal test was removed in #168 along
// with the GeneralizeOffer field. The quiet-moment suggestion is a
// daemon-side entity; the TUI no longer holds state for it that Esc
// could dismiss.)
