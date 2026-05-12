package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// TestApplyKeyApprovals_OpenLLMPanelExpandsByDefault pins #91:
// pressing '3' opens the LLM panel with the selected digest already
// expanded (no Enter required).
func TestApplyKeyApprovals_OpenLLMPanelExpandsByDefault(t *testing.T) {
	d := advisor.Digest{RequestID: "req-a", Effect: "allow", Host: "x"}
	m := Model{
		Cols: 100, Rows: 30,
		Focused: PaneApprovals,
		Digests: []advisor.Digest{d},
	}
	got, _ := Apply(m, KeyEvent{Rune: '3'})
	if !got.DigestExpanded {
		t.Errorf("LLM panel open did not set DigestExpanded; #91 wants expand-by-default")
	}
}

// TestApplyKeyLLM_EnterTogglesAfterDefaultExpand pins that Enter
// still toggles collapse/expand even though the default state is
// expanded (#91).
func TestApplyKeyLLM_EnterTogglesAfterDefaultExpand(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	m.DigestExpanded = true
	got, _ := Apply(m, KeyEvent{Key: KeyEnter})
	if got.DigestExpanded {
		t.Errorf("Enter on expanded did not collapse")
	}
	got2, _ := Apply(got, KeyEvent{Key: KeyEnter})
	if !got2.DigestExpanded {
		t.Errorf("Enter on collapsed did not expand")
	}
}

// TestRenderLLMPane_WrapsLongReason pins #91 wrap behavior: a digest
// whose reason exceeds the panel width produces multiple body lines
// for that field (rather than truncating).
func TestRenderLLMPane_WrapsLongReason(t *testing.T) {
	longReason := strings.Repeat("the reason is long and must wrap across multiple lines ", 5)
	d := advisor.Digest{
		Timestamp:  time.Unix(1_700_000_000, 0).UTC(),
		Effect:     "allow",
		Confidence: "high",
		Host:       "api.example.com",
		Reason:     longReason,
		RequestID:  "req-a",
		Method:     "GET",
		Scheme:     "https", Port: 443, Path: "/x",
	}
	m := Model{
		Cols: 80, Rows: 50,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelLLM,
		BottomPanelOpen: true,
		Digests:         []advisor.Digest{d},
		DigestSelected:  "req-a",
		DigestExpanded:  true,
	}
	// Drive directly through digestDetailLines with the panel inner
	// width to assert the wrap math without depending on render's
	// terminal-row arithmetic.
	lines := digestDetailLines(d, 80-len(llmSelectionPad))
	reasonLines := 0
	for _, l := range lines {
		if strings.Contains(l, "reason") || strings.HasPrefix(strings.TrimLeft(l, " "), longReason[:10]) {
			reasonLines++
		}
	}
	if reasonLines < 2 {
		t.Errorf("expected reason to wrap across >=2 lines; got %d. lines=%v", reasonLines, lines)
	}
	// Also: integration with the renderer doesn't crash.
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
}

// TestRenderLLMPane_NoInverseVideoInLLMBody pins that the inverse-
// video escape `\x1b[7m` does NOT appear adjacent to the LLM body
// rows — the side-bar marker replaces it (#91). The approvals pane
// may still emit \x1b[7m for its own selection; this test scopes by
// only generating a frame whose top pane has no selection.
func TestRenderLLMPane_NoInverseVideoOnLLMRows(t *testing.T) {
	d := advisor.Digest{
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
		Effect:    "allow", Confidence: "high",
		Host: "x", Reason: "ok", RequestID: "req-a",
	}
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelLLM,
		BottomPanelOpen: true,
		Digests:         []advisor.Digest{d},
		DigestSelected:  "req-a",
		DigestExpanded:  false, // compact form
		Selected:        -1,    // no approvals selection so no inverse video from the top
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b.String(), "\x1b[7m") {
		t.Errorf("LLM render still contains inverse-video markup; #91 wants side-bar only")
	}
}

// TestWrapAfterLabel_Indent verifies continuation lines indent
// under the label column.
func TestWrapAfterLabel_Indent(t *testing.T) {
	label := "  reason     : " // 15 cols
	value := "alpha bravo charlie delta echo foxtrot"
	out := wrapAfterLabel(label, value, 25)
	if len(out) < 2 {
		t.Fatalf("expected at least 2 wrap lines; got %d: %v", len(out), out)
	}
	if !strings.HasPrefix(out[0], label) {
		t.Errorf("first line missing label prefix: %q", out[0])
	}
	for i, l := range out[1:] {
		if !strings.HasPrefix(l, strings.Repeat(" ", len(label))) {
			t.Errorf("continuation %d missing indent: %q", i+1, l)
		}
	}
}
