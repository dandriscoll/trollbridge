package tui

import (
	"testing"
)

// urlsModel returns a Model with the URLs panel open, focused, local,
// and pre-populated with sample allow/deny entries. Used by the
// editor-verb tests so they all share the same starting state.
func urlsModel(selected int) Model {
	return Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList: []string{
			"GET https://api.example.com:443/v1/things",
			"https://docs.example.com:443/",
		},
		DenyList: []string{
			"https://evil.example.com:443/",
		},
		URLsSelected: selected,
	}
}

// TestApplyKeyURLs_DeleteRemovesSelected pins that the Delete key
// (and 'x' for back-compat) removes the selected entry and stores
// the undo state.
func TestApplyKeyURLs_DeleteRemovesSelected(t *testing.T) {
	cases := []struct {
		name string
		ev   KeyEvent
	}{
		{"KeyDelete", KeyEvent{Key: KeyDelete}},
		{"x rune", KeyEvent{Rune: 'x'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := urlsModel(0)
			got, cmd := Apply(m, c.ev)
			exec, ok := cmd.(CmdConsoleExec)
			if !ok {
				t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
			}
			want := "remove GET https://api.example.com:443/v1/things"
			if exec.Line != want {
				t.Errorf("exec.Line = %q, want %q", exec.Line, want)
			}
			if got.URLsUndo == nil {
				t.Fatalf("URLsUndo not populated")
			}
			if got.URLsUndo.Side != "allow" || got.URLsUndo.Pattern != "GET https://api.example.com:443/v1/things" {
				t.Errorf("URLsUndo = %+v", got.URLsUndo)
			}
		})
	}
}

// TestApplyKeyURLs_DeleteOnDenyEntryCapturesDenySide verifies the
// undo entry remembers the deny side for deny-list deletions.
func TestApplyKeyURLs_DeleteOnDenyEntryCapturesDenySide(t *testing.T) {
	m := urlsModel(2) // index 2 = first deny entry
	got, _ := Apply(m, KeyEvent{Key: KeyDelete})
	if got.URLsUndo == nil || got.URLsUndo.Side != "deny" {
		t.Fatalf("URLsUndo = %+v, want side=deny", got.URLsUndo)
	}
	if got.URLsUndo.Pattern != "https://evil.example.com:443/" {
		t.Errorf("URLsUndo.Pattern = %q", got.URLsUndo.Pattern)
	}
}

// TestApplyKeyURLs_CtrlZRestoresLastDelete pins the undo flow.
func TestApplyKeyURLs_CtrlZRestoresLastDelete(t *testing.T) {
	m := urlsModel(0)
	m.URLsUndo = &URLsUndoEntry{
		Pattern: "GET https://api.example.com:443/v1/things",
		Side:    "allow",
	}
	got, cmd := Apply(m, KeyEvent{Key: KeyCtrlZ})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	want := "allow GET https://api.example.com:443/v1/things"
	if exec.Line != want {
		t.Errorf("exec.Line = %q, want %q", exec.Line, want)
	}
	if got.URLsUndo != nil {
		t.Errorf("URLsUndo not cleared after restore: %+v", got.URLsUndo)
	}
}

// TestApplyKeyURLs_CtrlZWithoutUndoErrors verifies the no-state case
// reports an info-level error instead of doing nothing silently.
func TestApplyKeyURLs_CtrlZWithoutUndoErrors(t *testing.T) {
	m := urlsModel(0)
	got, cmd := Apply(m, KeyEvent{Key: KeyCtrlZ})
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone", cmd)
	}
	if got.LastErr == "" {
		t.Errorf("LastErr empty; want 'nothing to undo' style message")
	}
}

// TestApplyKeyURLs_PlusSwitchesToConsoleWithPrefill pins '+' (add)
// behavior: the bottom panel switches to console, input is prefilled
// with "allow ", and URLsPendingReturn flips on.
func TestApplyKeyURLs_PlusSwitchesToConsoleWithPrefill(t *testing.T) {
	m := urlsModel(0)
	got, _ := Apply(m, KeyEvent{Rune: '+'})
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel = %d, want BottomPanelConsole", got.BottomPanel)
	}
	if string(got.Console.Input) != "allow " {
		t.Errorf("Console.Input = %q, want %q", string(got.Console.Input), "allow ")
	}
	if got.Console.Cursor != len("allow ") {
		t.Errorf("Console.Cursor = %d, want %d", got.Console.Cursor, len("allow "))
	}
	if !got.URLsPendingReturn {
		t.Errorf("URLsPendingReturn = false, want true")
	}
}

// TestApplyKeyURLs_ApproveMovesDenyEntryToAllow pins 'a' (approve)
// on a deny-side entry: emits `move allow <pat>`.
func TestApplyKeyURLs_ApproveMovesDenyEntryToAllow(t *testing.T) {
	m := urlsModel(2) // first deny entry
	_, cmd := Apply(m, KeyEvent{Rune: 'a'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	want := "move allow https://evil.example.com:443/"
	if exec.Line != want {
		t.Errorf("exec.Line = %q, want %q", exec.Line, want)
	}
}

// TestApplyKeyURLs_DenyMovesAllowEntryToDeny pins 'd' on an
// allow-side entry: emits `move deny <pat>`.
func TestApplyKeyURLs_DenyMovesAllowEntryToDeny(t *testing.T) {
	m := urlsModel(0) // first allow entry
	_, cmd := Apply(m, KeyEvent{Rune: 'd'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	want := "move deny GET https://api.example.com:443/v1/things"
	if exec.Line != want {
		t.Errorf("exec.Line = %q, want %q", exec.Line, want)
	}
}

// TestApplyKeyURLs_ApproveOnAllowEntryIsNoOp pins the same-side
// case: 'a' on an entry already in allow does nothing but surface a
// status message.
func TestApplyKeyURLs_ApproveOnAllowEntryIsNoOp(t *testing.T) {
	m := urlsModel(0) // first allow entry
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("cmd = %T, want CmdNone", cmd)
	}
	if got.LastInfo == "" {
		t.Errorf("LastInfo empty; want 'already in allow' message")
	}
}

// TestApplyKeyURLs_EditPrefillsAndRemovesOriginal pins 'e': prefill
// with the selected pattern, fire `remove <p>`, store undo, set
// URLsPendingReturn.
func TestApplyKeyURLs_EditPrefillsAndRemovesOriginal(t *testing.T) {
	m := urlsModel(0)
	got, cmd := Apply(m, KeyEvent{Rune: 'e'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec (the immediate remove)", cmd)
	}
	if exec.Line != "remove GET https://api.example.com:443/v1/things" {
		t.Errorf("exec.Line = %q", exec.Line)
	}
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel = %d, want BottomPanelConsole", got.BottomPanel)
	}
	wantPrefill := "allow GET https://api.example.com:443/v1/things"
	if string(got.Console.Input) != wantPrefill {
		t.Errorf("Console.Input = %q, want %q", string(got.Console.Input), wantPrefill)
	}
	if got.URLsUndo == nil || got.URLsUndo.Side != "allow" {
		t.Errorf("URLsUndo = %+v", got.URLsUndo)
	}
	if !got.URLsPendingReturn {
		t.Errorf("URLsPendingReturn = false, want true")
	}
}

// TestApplyKeyURLs_EditOnDenyEntryPrefillsDeny verifies the prefill
// matches the entry's original side.
func TestApplyKeyURLs_EditOnDenyEntryPrefillsDeny(t *testing.T) {
	m := urlsModel(2) // first deny entry
	got, _ := Apply(m, KeyEvent{Rune: 'e'})
	want := "deny https://evil.example.com:443/"
	if string(got.Console.Input) != want {
		t.Errorf("Console.Input = %q, want %q", string(got.Console.Input), want)
	}
}

// TestApplyConsoleExec_URLsPendingReturnSnapsBack pins that after
// 'a' or 'e', the next ConsoleExecResult restores BottomPanel=URLs
// and clears the flag, then fires CmdURLsRefresh.
func TestApplyConsoleExec_URLsPendingReturnSnapsBack(t *testing.T) {
	m := urlsModel(0)
	m.BottomPanel = BottomPanelConsole
	m.URLsPendingReturn = true
	got, cmd := Apply(m, ConsoleExecResult{Line: "allow GET https://x/", Output: "ok"})
	if got.BottomPanel != BottomPanelURLs {
		t.Errorf("BottomPanel = %d, want BottomPanelURLs", got.BottomPanel)
	}
	if got.URLsPendingReturn {
		t.Errorf("URLsPendingReturn still true after snap-back")
	}
	if _, ok := cmd.(CmdURLsRefresh); !ok {
		t.Errorf("cmd = %T, want CmdURLsRefresh", cmd)
	}
}

// TestApplyKeyURLs_GeneralizeSingleSelectOpensCard pins #170: pressing
// 'g' on a single concrete URL opens the unified generalization card
// with the axis candidates for that entry (replacing the post-#168
// error stub). The card, not a LastErr, is the surface now.
func TestApplyKeyURLs_GeneralizeSingleSelectOpensCard(t *testing.T) {
	m := urlsModel(0) // GET https://api.example.com:443/v1/things
	m.URLsAnchor = -1
	got, _ := Apply(m, KeyEvent{Rune: 'g'})
	if got.GenCard == nil {
		t.Fatalf("g did not open a generalize card (LastErr=%q)", got.LastErr)
	}
	if len(got.GenCard.Candidates) == 0 {
		t.Fatalf("card has no candidates")
	}
	if got.LastErr != "" {
		t.Errorf("LastErr = %q; want empty when a card opens", got.LastErr)
	}
	// The single source entry is the selected URL.
	if c := got.GenCard.Current(); len(c.SourceEntries) != 1 {
		t.Errorf("single-select card SourceEntries = %v; want one", c.SourceEntries)
	}
}

// TestApplyKeyApprovals_DigitClearsURLsPendingReturn pins that an
// explicit panel-switch keystroke cancels a pending URLs return so
// the next exec does not yank the operator back to URLs.
func TestApplyKeyApprovals_DigitClearsURLsPendingReturn(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, URLsPendingReturn: true}
	got, _ := Apply(m, KeyEvent{Rune: '2'})
	if got.URLsPendingReturn {
		t.Errorf("URLsPendingReturn still true after digit switch")
	}
}
