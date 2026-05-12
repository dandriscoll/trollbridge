package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// digestAt returns a deterministic Digest for use in tests. Pass
// idx to vary RequestID; the timestamp increments by one second per
// idx so newer-vs-older ordering is unambiguous.
func digestAt(idx int) advisor.Digest {
	return advisor.Digest{
		Timestamp:  time.Unix(1_700_000_000+int64(idx), 0).UTC(),
		RequestID:  "req-" + string(rune('a'+idx)),
		Method:     "GET",
		Scheme:     "https-intercepted",
		Host:       "api.example.com",
		Port:       443,
		Path:       "/v1/things",
		Effect:     "allow",
		Confidence: "high",
		AdvisorID:  "adv-1",
		Reason:     "approved by policy",
		Outcome:    "allowed",
	}
}

// modelWithDigests builds a Model with the LLM panel open, focused,
// and the supplied digests installed (oldest-first in the slice so
// the newest-first display order matches index reversed).
func modelWithDigests(digests []advisor.Digest) Model {
	return Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelLLM,
		BottomPanelOpen: true,
		Digests:         digests,
		Selected:        -1,
	}
}

// TestApplyKey_ThreeOpensAndFocusesLLM pins #81 contract: '3' opens
// the LLM pane AND auto-focuses it for navigation. Mirrors the
// TestApplyKey_FourOpensAndFocusesURLs contract for the URLs pane.
func TestApplyKey_ThreeOpensAndFocusesLLM(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused: PaneApprovals,
		Digests: []advisor.Digest{digestAt(0), digestAt(1)},
	}
	got, cmd := Apply(m, KeyEvent{Rune: '3'})
	if got.BottomPanel != BottomPanelLLM {
		t.Errorf("BottomPanel = %d, want BottomPanelLLM", got.BottomPanel)
	}
	if !got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen = false; want true")
	}
	if got.Focused != PaneConsole {
		t.Errorf("Focused = %v after '3'; want PaneConsole (auto-focus)", got.Focused)
	}
	if got.DigestSelected != "req-b" {
		t.Errorf("DigestSelected = %q after '3'; want newest digest %q", got.DigestSelected, "req-b")
	}
	if _, ok := cmd.(CmdDigestRefresh); !ok {
		t.Errorf("Cmd = %T; want CmdDigestRefresh on '3' open", cmd)
	}
}

// TestApplyKeyLLM_NavigateDown moves the selection from the newest
// digest toward older ones with Down/j.
func TestApplyKeyLLM_NavigateDown(t *testing.T) {
	// digestAt(0) oldest, digestAt(2) newest in display order.
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1), digestAt(2)})
	m.DigestSelected = "req-c" // newest
	for _, ev := range []KeyEvent{{Key: KeyDown}, {Rune: 'j'}} {
		got, _ := Apply(m, ev)
		want := "req-b" // one older than newest
		if got.DigestSelected != want {
			t.Errorf("after %v: DigestSelected = %q, want %q", ev, got.DigestSelected, want)
		}
		m = got
		// Reset for the next iteration.
		m.DigestSelected = "req-c"
	}
}

// TestApplyKeyLLM_NavigateUp moves selection toward newer with Up/k.
func TestApplyKeyLLM_NavigateUp(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1), digestAt(2)})
	m.DigestSelected = "req-a" // oldest
	for _, ev := range []KeyEvent{{Key: KeyUp}, {Rune: 'k'}} {
		got, _ := Apply(m, ev)
		if got.DigestSelected != "req-b" {
			t.Errorf("after %v: DigestSelected = %q, want %q", ev, got.DigestSelected, "req-b")
		}
		m.DigestSelected = "req-a"
	}
}

// TestApplyKeyLLM_NavigateBoundedAtEnds: Up on newest stays; Down on
// oldest stays.
func TestApplyKeyLLM_NavigateBoundedAtEnds(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b" // newest
	got, _ := Apply(m, KeyEvent{Key: KeyUp})
	if got.DigestSelected != "req-b" {
		t.Errorf("Up at newest moved selection to %q; want %q", got.DigestSelected, "req-b")
	}
	m.DigestSelected = "req-a" // oldest
	got, _ = Apply(m, KeyEvent{Key: KeyDown})
	if got.DigestSelected != "req-a" {
		t.Errorf("Down at oldest moved selection to %q; want %q", got.DigestSelected, "req-a")
	}
}

// TestApplyKeyLLM_EnterTogglesExpansion: Enter sets DigestExpanded
// true on first press, false on second.
func TestApplyKeyLLM_EnterTogglesExpansion(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	got, _ := Apply(m, KeyEvent{Key: KeyEnter})
	if !got.DigestExpanded {
		t.Errorf("first Enter did not set DigestExpanded; got false")
	}
	got, _ = Apply(got, KeyEvent{Key: KeyEnter})
	if got.DigestExpanded {
		t.Errorf("second Enter did not collapse DigestExpanded; got true")
	}
}

// TestApplyKeyLLM_EnterOnEmptyIsNoop: Enter with no digest selected
// (e.g. empty list) does nothing.
func TestApplyKeyLLM_EnterOnEmptyIsNoop(t *testing.T) {
	m := modelWithDigests(nil)
	got, _ := Apply(m, KeyEvent{Key: KeyEnter})
	if got.DigestExpanded {
		t.Errorf("Enter on empty digest list set DigestExpanded; want false")
	}
}

// TestApplyKeyLLM_NavigateCollapsesExpansion: j/k while expanded
// collapses first, then moves.
func TestApplyKeyLLM_NavigateCollapsesExpansion(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = true
	got, _ := Apply(m, KeyEvent{Rune: 'j'})
	if got.DigestExpanded {
		t.Errorf("j while expanded did not collapse; DigestExpanded still true")
	}
	if got.DigestSelected != "req-a" {
		t.Errorf("j while expanded did not move selection; got %q want %q", got.DigestSelected, "req-a")
	}
}

// TestApplyKeyLLM_EscClosesPanel: under #87, Esc on the LLM panel
// closes the panel entirely (even when an expanded detail is
// showing). Enter remains the verb for collapse-but-keep-open.
func TestApplyKeyLLM_EscClosesPanel(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	m.DigestExpanded = true
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.BottomPanelOpen {
		t.Errorf("Esc did not close the LLM panel; BottomPanelOpen still true")
	}
	if got.DigestExpanded {
		t.Errorf("Esc did not clear DigestExpanded")
	}
	if got.Focused != PaneApprovals {
		t.Errorf("Esc did not defocus; want PaneApprovals, got %v", got.Focused)
	}
}

// TestApplyKeyLLM_QDefocuses: 'q' while focused in the LLM panel
// returns to approvals (does NOT quit the TUI — the existing quit
// path only fires from approvals focus).
func TestApplyKeyLLM_QDefocuses(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	got, cmd := Apply(m, KeyEvent{Rune: 'q'})
	if got.Quit {
		t.Errorf("'q' in LLM panel set Quit; want defocus only")
	}
	if got.Focused != PaneApprovals {
		t.Errorf("'q' did not defocus; got Focused=%v", got.Focused)
	}
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("Cmd = %T; want CmdNone (no quit)", cmd)
	}
}

// TestApplyKeyLLM_DigitClosesPanel: '0' or '3' while focused in the
// LLM panel closes the panel and defocuses (matches URLs behavior).
func TestApplyKeyLLM_DigitClosesPanel(t *testing.T) {
	for _, key := range []rune{'0', '3'} {
		t.Run(string(key), func(t *testing.T) {
			m := modelWithDigests([]advisor.Digest{digestAt(0)})
			m.DigestSelected = "req-a"
			got, _ := Apply(m, KeyEvent{Rune: key})
			if got.BottomPanelOpen {
				t.Errorf("%q did not close panel; BottomPanelOpen still true", key)
			}
			if got.Focused != PaneApprovals {
				t.Errorf("%q did not defocus; got Focused=%v", key, got.Focused)
			}
			if got.DigestExpanded {
				t.Errorf("%q did not reset DigestExpanded; still true", key)
			}
		})
	}
}

// TestDigestTickResult_PreservesSelectionByID: a new tick that
// reorders or extends the ring keeps the selection on the same
// RequestID.
func TestDigestTickResult_PreservesSelectionByID(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-a" // not the newest
	// Tick brings a new digest (req-c) into the ring; req-a still
	// present.
	got, _ := Apply(m, DigestTickResult{
		Digests: []advisor.Digest{digestAt(0), digestAt(1), digestAt(2)},
	})
	if got.DigestSelected != "req-a" {
		t.Errorf("DigestTickResult shifted selection from %q to %q", "req-a", got.DigestSelected)
	}
}

// TestDigestTickResult_EvictedSelectionFallsBackToNewest: when the
// previously-selected digest is no longer in the ring, fall back to
// the newest.
func TestDigestTickResult_EvictedSelectionFallsBackToNewest(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	// New tick: req-a evicted, only req-c and req-d.
	got, _ := Apply(m, DigestTickResult{
		Digests: []advisor.Digest{digestAt(2), digestAt(3)},
	})
	if got.DigestSelected != "req-d" {
		t.Errorf("Fallback after eviction = %q; want newest %q", got.DigestSelected, "req-d")
	}
}

// TestDigestTickResult_EmptyClearsSelection: an empty digest tick
// (e.g. after a daemon restart) clears DigestSelected.
func TestDigestTickResult_EmptyClearsSelection(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	m.DigestExpanded = true
	got, _ := Apply(m, DigestTickResult{Digests: nil})
	if got.DigestSelected != "" {
		t.Errorf("Empty tick did not clear DigestSelected; got %q", got.DigestSelected)
	}
	if got.DigestExpanded {
		t.Errorf("Empty tick did not clear DigestExpanded")
	}
}

// TestRenderLLMPane_SelectionCursorVisible: with a digest selected
// (not expanded), the rendered output contains the inverse-video
// ANSI sequence on the matching row.
func TestRenderLLMPane_SelectionCursorVisible(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	// Inverse-video sequence used by the renderer for selection.
	if !strings.Contains(out, "\x1b[7m") {
		t.Errorf("rendered output missing inverse-video escape (\\x1b[7m); first 600: %q", first(out, 600))
	}
}

// TestRenderLLMPane_NewLegendShown: the panel header carries the
// new keystroke hints.
func TestRenderLLMPane_NewLegendShown(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"Enter", "Esc", "nav", "detail"} {
		if !strings.Contains(out, want) {
			t.Errorf("LLM panel header missing %q; first 600: %q", want, first(out, 600))
		}
	}
}

// TestRenderLLMPane_ExpandedInline: with a tall enough body, the
// expanded detail draws inline; at least one peer-digest row
// remains visible.
func TestRenderLLMPane_ExpandedInline(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = true
	// Rows=40 → bodyRows ≈ 40, bottomRows ≈ 20: comfortably fits
	// header (1) + detail (8) + peers.
	m.Rows = 40
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	// Inline mode renders peer rows AND detail fields. The "── llm"
	// header should appear (panel header, not modal header).
	if !strings.Contains(out, "── llm ──") {
		t.Errorf("inline expand did not draw panel header; first 600: %q", first(out, 600))
	}
	if strings.Contains(out, "── llm detail ──") {
		t.Errorf("inline expand wrongly drew the modal header (── llm detail ──)")
	}
	// Detail field labels.
	for _, want := range []string{"request_id", "effect", "advisor_id", "reason"} {
		if !strings.Contains(out, want) {
			t.Errorf("inline expand missing detail field label %q", want)
		}
	}
}

// TestRenderLLMPane_ExpandedPromotesToModal: at a small terminal
// size, the detail does not fit inline; render() emits the modal
// view in place of the two-pane split.
func TestRenderLLMPane_ExpandedPromotesToModal(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = true
	// Rows=12 → bodyRows=12 → topRows=6 → bottomRows=6. Detail
	// requires 1+8+1=10 rows: does not fit. Modal promotes.
	m.Rows = 12
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "── llm detail ──") {
		t.Errorf("overflow case did not promote to modal; first 600: %q", first(out, 600))
	}
	// Detail fields present in modal.
	for _, want := range []string{"request_id", "effect", "advisor_id"} {
		if !strings.Contains(out, want) {
			t.Errorf("modal missing detail field label %q", want)
		}
	}
	// Modal suppresses the normal split — the approvals-pane border
	// label ("ops") and the "── llm ──" (non-modal) header should be
	// absent.
	if strings.Contains(out, "── llm ──") {
		t.Errorf("modal wrongly drew the non-modal panel header (── llm ──) alongside the modal")
	}
}

// TestRenderLLMPane_ModalEscReturnsToList: after an Esc keystroke
// while modal-expanded, render no longer contains the modal header
// and the normal panel renders again.
func TestRenderLLMPane_ModalEscReturnsToList(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = true
	m.Rows = 12
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.DigestExpanded {
		t.Errorf("Esc in modal did not collapse expansion")
	}
	var b strings.Builder
	if err := render(&b, got); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if strings.Contains(out, "── llm detail ──") {
		t.Errorf("after Esc, modal header still present in render output")
	}
}

// TestShouldRenderLLMModal_DecisionBoundary pins the modal-promotion
// rule: panelRows >= 10 stays inline; below promotes to modal.
func TestShouldRenderLLMModal_DecisionBoundary(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	m.DigestExpanded = true
	// bodyRows=20 → topRows=10 → bottomRows=10 → exactly fits (1+8+1).
	if shouldRenderLLMModal(m, 20) {
		t.Errorf("modal-promotion fired at bodyRows=20; bottom should fit 10 rows")
	}
	// bodyRows=18 → topRows=9 → bottomRows=9 → does NOT fit.
	if !shouldRenderLLMModal(m, 18) {
		t.Errorf("modal-promotion did not fire at bodyRows=18; bottom is 9 rows")
	}
}

// TestShouldRenderLLMModal_OnlyWhenLLMPanelOpenAndExpanded: the
// modal short-circuit applies only when the LLM panel is open,
// expanded, and a digest is selected.
func TestShouldRenderLLMModal_OnlyWhenLLMPanelOpenAndExpanded(t *testing.T) {
	base := modelWithDigests([]advisor.Digest{digestAt(0)})
	base.DigestSelected = "req-a"
	cases := []struct {
		name string
		mod  func(Model) Model
	}{
		{"panel closed", func(m Model) Model { m.BottomPanelOpen = false; m.DigestExpanded = true; return m }},
		{"wrong panel", func(m Model) Model { m.BottomPanel = BottomPanelInfo; m.DigestExpanded = true; return m }},
		{"not expanded", func(m Model) Model { m.DigestExpanded = false; return m }},
		{"no selection", func(m Model) Model { m.DigestExpanded = true; m.DigestSelected = ""; return m }},
	}
	for _, tc := range cases {
		m := tc.mod(base)
		if shouldRenderLLMModal(m, 10) {
			t.Errorf("%s: shouldRenderLLMModal returned true; want false", tc.name)
		}
	}
}
