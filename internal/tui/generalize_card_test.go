package tui

import (
	"strings"
	"testing"
)

// genModel builds a URLs-pane model whose allow list contains two
// entries that differ only in the trailing path segment — a non-
// trivial fixture (insight): a no-op selection would NOT produce the
// url_segment group candidate, so the multi-select test actually
// exercises the detector.
func genModel() Model {
	return Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		URLsAnchor:      -1,
		AllowList: []string{
			"GET https://api.example.com/v1/users/123",
			"GET https://api.example.com/v1/users/456",
		},
		DenyList:     []string{"https://evil.example.com/"},
		URLsSelected: 0,
	}
}

// TestGeneralize_MultiSelectRunsDetectorOnSubset pins #170 entry point
// 2: Shift-Down builds a 2-entry range, and `g` runs the deterministic
// detector over just that subset, producing the url_segment group
// pattern.
func TestGeneralize_MultiSelectRunsDetectorOnSubset(t *testing.T) {
	m := genModel()
	// Shift-down from index 0 → anchor 0, cursor 1: selects both
	// /users/123 and /users/456.
	m, _ = Apply(m, KeyEvent{Key: KeyShiftDown})
	if m.URLsAnchor != 0 || m.URLsSelected != 1 {
		t.Fatalf("shift-down range: anchor=%d cursor=%d, want 0,1", m.URLsAnchor, m.URLsSelected)
	}
	got, _ := Apply(m, KeyEvent{Rune: 'g'})
	if got.GenCard == nil {
		t.Fatalf("g over multi-selection opened no card (LastErr=%q)", got.LastErr)
	}
	c := got.GenCard.Current()
	if c.SuggestedPattern != "GET https://api.example.com/v1/users/*" {
		t.Errorf("pattern = %q, want the url_segment group pattern", c.SuggestedPattern)
	}
	if len(c.SourceEntries) != 2 {
		t.Errorf("group SourceEntries = %v, want both selected entries", c.SourceEntries)
	}
	if !strings.Contains(got.GenCard.SourceDesc, "2 selected") {
		t.Errorf("SourceDesc = %q, want it to name 2 selected entries", got.GenCard.SourceDesc)
	}
}

// TestGeneralize_PlainNavResetsAnchor pins that a plain (unshifted)
// arrow clears an in-flight multi-selection so `g` falls back to
// single-select.
func TestGeneralize_PlainNavResetsAnchor(t *testing.T) {
	m := genModel()
	m, _ = Apply(m, KeyEvent{Key: KeyShiftDown}) // anchor 0, cursor 1
	m, _ = Apply(m, KeyEvent{Key: KeyDown})       // plain nav resets
	if m.URLsAnchor != -1 {
		t.Fatalf("plain nav did not reset anchor: %d", m.URLsAnchor)
	}
}

// TestGeneralize_CardModalAcceptWritesPattern pins #170 accept: 'a'
// writes the current candidate's pattern through the same console
// configwrite path a typed `allow <pat>` uses, then dismisses the card.
func TestGeneralize_CardModalAcceptWritesPattern(t *testing.T) {
	m := genModel()
	m, _ = Apply(m, KeyEvent{Key: KeyShiftDown})
	m, _ = Apply(m, KeyEvent{Rune: 'g'})
	pattern := m.GenCard.Current().SuggestedPattern
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	if got.GenCard != nil {
		t.Errorf("accept did not dismiss the card")
	}
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("accept cmd = %T, want CmdConsoleExec", cmd)
	}
	if exec.Line != "allow "+pattern {
		t.Errorf("accept line = %q, want %q", exec.Line, "allow "+pattern)
	}
	if !got.URLsPendingReturn {
		t.Errorf("accept did not set URLsPendingReturn for the snap-back refresh")
	}
}

// TestGeneralize_CardModalDeclineAndTab pins decline (esc/d dismiss
// without writing) and axis rotation (tab cycles candidates).
func TestGeneralize_CardModalDeclineAndTab(t *testing.T) {
	m := genModel()
	m, _ = Apply(m, KeyEvent{Rune: 'g'}) // single-select on index 0: multiple axes
	if n := len(m.GenCard.Candidates); n < 2 {
		t.Fatalf("expected ≥2 axis candidates for tab rotation, got %d", n)
	}
	rotated, _ := Apply(m, KeyEvent{Key: KeyTab})
	if rotated.GenCard.AxisIndex != 1 {
		t.Errorf("tab AxisIndex = %d, want 1", rotated.GenCard.AxisIndex)
	}
	// Original model's card is unchanged (no shared-pointer mutation).
	if m.GenCard.AxisIndex != 0 {
		t.Errorf("tab mutated the input model's card AxisIndex to %d", m.GenCard.AxisIndex)
	}
	for _, k := range []KeyEvent{{Rune: 'd'}, {Key: KeyEsc}} {
		dis, cmd := Apply(m, k)
		if dis.GenCard != nil {
			t.Errorf("%+v did not dismiss the card", k)
		}
		if _, ok := cmd.(CmdNone); !ok {
			t.Errorf("%+v cmd = %T, want CmdNone (no write)", k, cmd)
		}
	}
}

// TestGeneralize_CardModalSwallowsOtherKeys pins that while the card is
// up, non-card keys do not leak to the underlying pane (a/d are accept/
// decline, not approve/deny; arbitrary keys are no-ops).
func TestGeneralize_CardModalSwallowsOtherKeys(t *testing.T) {
	m := genModel()
	m, _ = Apply(m, KeyEvent{Rune: 'g'})
	got, cmd := Apply(m, KeyEvent{Rune: 'x'})
	if got.GenCard == nil {
		t.Errorf("a non-card key dismissed the card")
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("non-card key cmd = %T, want CmdNone (swallowed)", cmd)
	}
}

// TestGeneralize_NoCandidateSurfacesError pins the no-generalization
// path: `g` on an entry with no applicable axis surfaces a clear error
// and opens no card.
func TestGeneralize_NoCandidateSurfacesError(t *testing.T) {
	m := genModel()
	m.AllowList = []string{"* example.com"} // method already *, host is eTLD+1, no path
	m.DenyList = nil
	m.URLsSelected = 0
	m.URLsAnchor = -1
	got, _ := Apply(m, KeyEvent{Rune: 'g'})
	if got.GenCard != nil {
		t.Errorf("expected no card for an ungeneralizable entry")
	}
	if !strings.Contains(got.LastErr, "no generalization") {
		t.Errorf("LastErr = %q, want a 'no generalization' message", got.LastErr)
	}
}

// TestGeneralize_CardRenderFitsWidth pins the literal #170 defect: the
// card lines never exceed the inner width, so accept/decline keys can't
// be pushed off the right edge. Reverting the runeTrunc fit makes the
// long pattern/key line exceed inner and this goes red.
func TestGeneralize_CardRenderFitsWidth(t *testing.T) {
	m := genModel()
	m, _ = Apply(m, KeyEvent{Key: KeyShiftDown})
	m, _ = Apply(m, KeyEvent{Rune: 'g'})
	for _, narrow := range []int{40, 60, 100} {
		inner := narrow - 2
		lines := formatGeneralizeCard(*m.GenCard, inner)
		if len(lines) == 0 {
			t.Fatalf("no card lines at width %d", narrow)
		}
		for i, l := range lines {
			if visible := visibleLen(l); visible > inner {
				t.Errorf("width %d: card line %d visible width %d > inner %d: %q", narrow, i, visible, inner, l)
			}
		}
	}
}
