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

// TestApplyKeyLLM_NavigateKeepsExpanded: j/k while expanded moves
// selection AND keeps the new selection expanded (#91 — expand-by-
// default). The pre-#91 behavior auto-collapsed on nav.
func TestApplyKeyLLM_NavigateKeepsExpanded(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = true
	got, _ := Apply(m, KeyEvent{Rune: 'j'})
	if !got.DigestExpanded {
		t.Errorf("j collapsed expansion; #91 keeps it open")
	}
	if got.DigestSelected != "req-a" {
		t.Errorf("j did not move selection; got %q want %q", got.DigestSelected, "req-a")
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

// TestRenderLLMPane_SelectionCursorVisible: with a digest selected,
// the rendered output marks the selected row(s) with the leading
// side-bar (#91). Replaces the prior inverse-video block highlight.
func TestRenderLLMPane_SelectionCursorVisible(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0), digestAt(1)})
	m.DigestSelected = "req-b"
	m.DigestExpanded = false // compact form so we test the leader, not the detail
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, llmSelectionBar) {
		t.Errorf("LLM render missing leading side-bar %q; first 600: %q", llmSelectionBar, first(out, 600))
	}
	// The all-white highlight should be gone from the LLM panel.
	// (other panes — approvals — may still use inverse video for
	// their own selection signal, so don't fail on its global
	// presence; restrict to the LLM lines by searching for the
	// bar-color escape next to a digit-time string.)
}

// TestRenderLLMPane_NewLegendShown: the panel header carries the
// updated keystroke hints (#91 — "collapse/expand" wording).
func TestRenderLLMPane_NewLegendShown(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"Enter", "Esc", "nav", "collapse/expand"} {
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
	// Inline mode renders peer rows AND detail fields. The "llm"
	// pane label (now embedded in the bordered top row, #88) should
	// appear.
	if !strings.Contains(out, "llm") {
		t.Errorf("inline expand did not draw panel header; first 600: %q", first(out, 600))
	}
	if strings.Contains(out, "── llm detail ──") {
		t.Errorf("inline expand wrongly drew the modal header (── llm detail ──)")
	}
	// Detail field labels (request_id dropped per #92).
	for _, want := range []string{"effect", "advisor_id", "reason"} {
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
	// Detail fields present in modal (request_id dropped per #92).
	for _, want := range []string{"effect", "advisor_id"} {
		if !strings.Contains(out, want) {
			t.Errorf("modal missing detail field label %q", want)
		}
	}
	// Modal suppresses the normal split — the non-modal LLM panel
	// chrome (top-border "llm" label, bottom-border [Enter]
	// collapse/expand hint) should be absent.
	if strings.Contains(out, "── llm ──") || strings.Contains(out, "[Enter] collapse/expand") {
		t.Errorf("modal wrongly drew the non-modal panel chrome alongside the modal")
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
// rule: with the panel chrome consuming top + bottom border rows
// (#88) and the actual wrapped detail line count (#105 cleanup —
// llmDetailLineCountFor replaces the static 10-line estimate),
// inline needs panelRows >= 2 + actualDetailLines + 1.
//
// digestAt(0) at cols=100 wraps to 7 lines (no overflow on url or
// reason at width=98), so inline needs panelRows >= 10.
func TestShouldRenderLLMModal_DecisionBoundary(t *testing.T) {
	m := modelWithDigests([]advisor.Digest{digestAt(0)})
	m.DigestSelected = "req-a"
	m.DigestExpanded = true
	// bodyRows=20 → topRows=10 → bottomRows=10 → exactly fits 7+2+1.
	if shouldRenderLLMModal(m, 20) {
		t.Errorf("modal-promotion fired at bodyRows=20; bottom should fit 10 rows for a 7-line detail")
	}
	// bodyRows=18 → topRows=9 → bottomRows=9 → does NOT fit (need 10).
	if !shouldRenderLLMModal(m, 18) {
		t.Errorf("modal-promotion did not fire at bodyRows=18; bottom is 9 rows but detail+chrome+peer needs 10")
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

// digestsN builds N digests, oldest at index 0, newest at N-1, so
// digest "req-<rune('a'+i)>" maps to display index (N-1)-i.
func digestsN(n int) []advisor.Digest {
	out := make([]advisor.Digest, n)
	for i := 0; i < n; i++ {
		out[i] = digestAt(i)
	}
	return out
}

// TestLLMDigestStartIndex_NewestSelectedReturnsHead pins that when
// the selection is the newest digest (display index 0), iteration
// starts from the top of the display (#117, updated for #198 to
// use display indices). Post-#198, llmDigestStartIndex returns a
// display index (0 = newest in TIME mode), and the render loop
// iterates forward from that index.
func TestLLMDigestStartIndex_NewestSelectedReturnsHead(t *testing.T) {
	m := modelWithDigests(digestsN(20))
	m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID // newest = display idx 0
	got := llmDigestStartIndex(m, 5)
	if got != 0 {
		t.Errorf("start = %d, want 0 (newest selected → top of display)", got)
	}
}

// TestLLMDigestStartIndex_NoSelectionReturnsHead pins that an empty
// DigestSelected leaves the iteration starting from the top of
// the display.
func TestLLMDigestStartIndex_NoSelectionReturnsHead(t *testing.T) {
	m := modelWithDigests(digestsN(20))
	m.DigestSelected = ""
	got := llmDigestStartIndex(m, 5)
	if got != 0 {
		t.Errorf("start = %d, want 0 (no selection → top of display)", got)
	}
}

// TestLLMDigestStartIndex_EmptyDigestsReturnsMinusOne pins the
// boundary case — an empty digest slice. The caller's `i >= 0`
// loop guard immediately exits.
func TestLLMDigestStartIndex_EmptyDigestsReturnsMinusOne(t *testing.T) {
	m := modelWithDigests(nil)
	if got := llmDigestStartIndex(m, 5); got != -1 {
		t.Errorf("start = %d, want -1 for empty digest slice", got)
	}
}

// TestLLMDigestStartIndex_SelectionWithinWindowReturnsHead pins
// that when the selection is within the visible bodyLines window
// from the top, iteration still starts from the top — no shift.
// Post-#198: display index 0 = top of display.
func TestLLMDigestStartIndex_SelectionWithinWindowReturnsHead(t *testing.T) {
	digests := digestsN(20)
	m := modelWithDigests(digests)
	// Display index 3 is digests[len-1-3] = digests[16] in TIME mode.
	m.DigestSelected = digests[16].RequestID
	got := llmDigestStartIndex(m, 5) // budget 5; display idx 3 fits.
	if got != 0 {
		t.Errorf("start = %d, want 0 (selection at display idx 3 fits in budget 5)", got)
	}
}

// TestLLMDigestStartIndex_SelectionBelowWindowShifts pins the core
// fix: when the selection sits below the visible window, the
// start shifts so the selection is the last visible row
// (anchor-at-bottom). Post-#198: shift = displayIdx - budget + 1.
func TestLLMDigestStartIndex_SelectionBelowWindowShifts(t *testing.T) {
	digests := digestsN(20)
	m := modelWithDigests(digests)
	// Pick display index 10 (i.e., digests[len-1-10] = digests[9]).
	m.DigestSelected = digests[9].RequestID
	// With bodyLines=5 and no expanded extra, budget=5.
	// start = displayIdx - budget + 1 = 10 - 5 + 1 = 6.
	got := llmDigestStartIndex(m, 5)
	want := 6
	if got != want {
		t.Errorf("start = %d, want %d (display idx 10, budget 5)", got, want)
	}
}

// TestLLMDigestStartIndex_ExpandedReducesBudget pins that the
// expanded-detail extra rows reduce the digest budget — and that
// the start shifts further so the selection still lands within the
// reduced window.
func TestLLMDigestStartIndex_ExpandedReducesBudget(t *testing.T) {
	digests := digestsN(20)
	m := modelWithDigests(digests)
	m.DigestSelected = digests[9].RequestID // display idx 10
	m.DigestExpanded = true
	// llmDetailLineCountFor falls back to llmDetailLineCount=10 when
	// the panel width hasn't been set for wrapping; with m.Cols=100
	// the detail wraps differently — call the helper to capture the
	// exact value the production code sees.
	extra := llmDetailLineCountFor(m) - 1
	if extra < 0 {
		extra = 0
	}
	bodyLines := 10
	digestBudget := bodyLines - extra
	if digestBudget < 1 {
		digestBudget = 1
	}
	want := 10 - digestBudget + 1
	if want < 0 {
		want = 0
	}
	if got := llmDigestStartIndex(m, bodyLines); got != want {
		t.Errorf("start = %d, want %d (expanded extra=%d budget=%d, display idx 10)", got, want, extra, digestBudget)
	}
}

// TestRenderLLMPane_SelectionOutsideWindowStaysVisible is the
// render-level integration test for #117. Build a model with 20
// digests, select one outside the natural newest-first window, and
// assert the selected digest's identifier appears in the rendered
// output. Before the scroll fix this test would fail because the
// renderer's hardcoded "start from newest" stopped before reaching
// the selection.
func TestRenderLLMPane_SelectionOutsideWindowStaysVisible(t *testing.T) {
	digests := digestsN(20)
	m := modelWithDigests(digests)
	m.Cols = 100
	// Pick display index 10 — well outside any reasonable bodyLines.
	selected := digests[9]
	m.DigestSelected = selected.RequestID
	m.DigestExpanded = false // inline summaries; one row per digest.

	var b strings.Builder
	renderLLMPane(&b, m, 7) // 7 rows for the panel; 5 rows body after borders.
	out := b.String()
	if !strings.Contains(out, selected.RequestID) {
		// One-line summary may omit the RequestID entirely (timestamp +
		// host shown); assert the timestamp instead.
		ts := selected.Timestamp.Local().Format("15:04:05")
		if !strings.Contains(out, ts) {
			t.Errorf("selected digest (req=%q ts=%q) not in rendered output:\n%s",
				selected.RequestID, ts, out)
		}
	}
}
