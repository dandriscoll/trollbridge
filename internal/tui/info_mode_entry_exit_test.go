package tui

import "testing"

// TestApplyKey_ShiftUpInURLsPaneDoesNotOpenInfo pins #171 bug 1 at the
// reducer layer: once the parser emits a real KeyShiftUp (instead of a
// leaked '2' rune), Shift-Up in the URLs pane must not switch the
// bottom panel to Info. Shift-Up is inert in this job (issue #170 gives
// it multi-select meaning).
func TestApplyKey_ShiftUpInURLsPaneDoesNotOpenInfo(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
	}
	for _, k := range []KeyCode{KeyShiftUp, KeyShiftDown} {
		got, _ := Apply(m, KeyEvent{Key: k})
		if got.BottomPanel == BottomPanelInfo {
			t.Errorf("%v opened the info panel; #171 says it must not", k)
		}
		if got.BottomPanel != BottomPanelURLs || !got.BottomPanelOpen {
			t.Errorf("%v disturbed the URLs panel: panel=%v open=%v", k, got.BottomPanel, got.BottomPanelOpen)
		}
	}
}

// TestApplyKey_InfoPanelIsNeverConsoleFocused pins #171 bug 2: opening
// the info panel from a console-focused pane (URLs) must leave focus on
// the approvals pane, so the panel is not a dead-focus trap. With
// Focused==PaneConsole and BottomPanel==Info the dispatch falls through
// to applyKeyConsole, which swallows digit keys into the hidden console
// input — the reported "0/4 do nothing, only esc closes".
func TestApplyKey_InfoPanelIsNeverConsoleFocused(t *testing.T) {
	// Start in the URLs pane (console-focused), then press '2' to open
	// info — the exact path the leaked rune took.
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
	}
	got, _ := Apply(m, KeyEvent{Rune: '2'})
	if got.BottomPanel != BottomPanelInfo || !got.BottomPanelOpen {
		t.Fatalf("'2' did not open info panel: panel=%v open=%v", got.BottomPanel, got.BottomPanelOpen)
	}
	if got.Focused != PaneApprovals {
		t.Fatalf("info panel left Focused=%v; want PaneApprovals (not a dead-focus trap)", got.Focused)
	}

	// From info, '4' must return to the URLs pane and '0' must close.
	back, _ := Apply(got, KeyEvent{Rune: '4'})
	if back.BottomPanel != BottomPanelURLs || !back.BottomPanelOpen {
		t.Errorf("'4' from info did not return to URLs: panel=%v open=%v", back.BottomPanel, back.BottomPanelOpen)
	}
	closed, _ := Apply(got, KeyEvent{Rune: '0'})
	if closed.BottomPanelOpen {
		t.Errorf("'0' from info did not close the panel")
	}
}
