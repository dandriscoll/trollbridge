package tui

import (
	"strings"
	"testing"
	"time"
)

// TestOpenMode_KeysEmitCommands (#209): 'o' opens/extends, 'c' closes.
func TestOpenMode_KeysEmitCommands(t *testing.T) {
	m := Model{Cols: 100, Rows: 20, Focused: PaneApprovals, Selected: -1}
	_, cmd := applyKeyApprovals(m, KeyEvent{Rune: 'o'})
	oc, ok := cmd.(CmdOpenMode)
	if !ok || oc.Close {
		t.Fatalf("'o' => %#v, want CmdOpenMode{Close:false}", cmd)
	}
	_, cmd = applyKeyApprovals(m, KeyEvent{Rune: 'c'})
	oc, ok = cmd.(CmdOpenMode)
	if !ok || !oc.Close {
		t.Fatalf("'c' => %#v, want CmdOpenMode{Close:true}", cmd)
	}
}

// TestOpenMode_ReducerSetsOpenUntil (#209): an OpenModeResult updates
// Model.OpenUntil; an error result leaves it unchanged.
func TestOpenMode_ReducerSetsOpenUntil(t *testing.T) {
	until := time.Now().Add(time.Minute)
	m, _ := Apply(Model{}, OpenModeResult{Active: true, Until: until})
	if !m.OpenUntil.Equal(until) {
		t.Fatalf("OpenUntil = %v, want %v", m.OpenUntil, until)
	}
	prior := m.OpenUntil
	m, _ = Apply(m, OpenModeResult{Err: errSentinel})
	if !m.OpenUntil.Equal(prior) {
		t.Errorf("error result must not change OpenUntil; got %v", m.OpenUntil)
	}
}

var errSentinel = &stubErr{}

type stubErr struct{}

func (*stubErr) Error() string { return "stub" }

// TestOpenMode_RenderBorderAndFooter (#209): while open, the approvals
// pane chrome renders amber and the footer advertises [c] close; while
// closed it uses the focus color and advertises [o] open. The amber
// escape MUST be absent when closed (else the color is unconditional).
func TestOpenMode_RenderBorderAndFooter(t *testing.T) {
	base := Model{Cols: 100, Rows: 12, Focused: PaneApprovals, Selected: -1}

	// Closed.
	var closed strings.Builder
	renderApprovalsPane(&closed, base, base.Rows)
	co := closed.String()
	if strings.Contains(co, colorOpenMode) {
		t.Errorf("closed pane must NOT contain the amber open-mode escape")
	}
	if !strings.Contains(co, "[o] open") {
		t.Errorf("closed footer should advertise [o] open:\n%s", co)
	}

	// Open (expiry in the future).
	openM := base
	openM.OpenUntil = time.Now().Add(45 * time.Second)
	var open strings.Builder
	renderApprovalsPane(&open, openM, openM.Rows)
	op := open.String()
	if !strings.Contains(op, colorOpenMode) {
		t.Errorf("open pane must render the amber open-mode border escape")
	}
	if !strings.Contains(op, "[c] close") {
		t.Errorf("open footer should advertise [c] close:\n%s", op)
	}
}
