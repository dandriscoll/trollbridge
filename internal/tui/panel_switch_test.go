package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyKey_NumberedKeysSwitchBottomPanelInApprovalsFocus pins #66:
// 1/2/3/4 with approvals pane focus cycle through the bottom panels.
func TestApplyKey_NumberedKeysSwitchBottomPanelInApprovalsFocus(t *testing.T) {
	cases := []struct {
		key  rune
		want BottomPanel
	}{
		{'1', BottomPanelConsole},
		{'2', BottomPanelInfo},
		{'3', BottomPanelLLM},
		{'4', BottomPanelURLs},
	}
	for _, c := range cases {
		t.Run(string(c.key), func(t *testing.T) {
			m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
			got, _ := Apply(m, KeyEvent{Rune: c.key})
			if got.BottomPanel != c.want {
				t.Errorf("BottomPanel = %d, want %d", got.BottomPanel, c.want)
			}
		})
	}
}

// TestApplyKey_NumberedKeysPassThroughInConsoleFocus pins that when
// the console pane has focus, numbered keys are typed (not consumed
// as panel-switch keystrokes). This keeps the operator's typing
// in-tact when the console is the active pane.
func TestApplyKey_NumberedKeysPassThroughInConsoleFocus(t *testing.T) {
	// Start with a panel open so console focus is reachable (#66
	// reactivation: Tab is a no-op when the bottom pane is closed).
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		Console:         ConsoleModel{Prompt: "> "},
	}
	got, _ := Apply(m, KeyEvent{Rune: '3'})
	// Console focus consumes printable runes into the input line.
	if got.BottomPanel != m.BottomPanel {
		t.Errorf("BottomPanel should not have changed from starting value %d; got %d", m.BottomPanel, got.BottomPanel)
	}
	if string(got.Console.Input) != "3" {
		t.Errorf("Console.Input = %q, want %q", string(got.Console.Input), "3")
	}
}

// TestRenderLLMPane_SmokeRendersDigests pins that the LLM panel
// produces a non-empty render frame including digest content.
func TestRenderLLMPane_SmokeRendersDigests(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel:     BottomPanelLLM,
		BottomPanelOpen: true,
		Digests: []advisor.Digest{
			{
				Timestamp: time.Unix(1_700_000_000, 0).UTC(),
				Effect:    "allow",
				Confidence: "high",
				Host:      "api.example.com",
				Reason:    "matches operator-trusted API host pattern",
			},
		},
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()
	for _, want := range []string{"llm", "allow", "api.example.com", "matches operator-trusted"} {
		if !strings.Contains(out, want) {
			t.Errorf("LLM panel render missing %q in output", want)
		}
	}
}

// TestRender_DefaultState_OnlyApprovalsRenders is the load-bearing
// pin for the #66 reactivation: with zero key events, the TUI renders
// only the approvals pane. No console prompt, no info/llm/urls panel
// header, no console pane bottom border.
func TestRender_DefaultState_OnlyApprovalsRenders(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()

	// Approvals pane MUST render.
	if !strings.Contains(out, "operations") {
		t.Errorf("approvals pane label missing from default render; first 400: %q", first(out, 400))
	}
	// Bottom pane must NOT render in any of its forms.
	mustNotContain := []string{
		"trollbridge> ", // console prompt
		"── info ──",
		"── llm ──",
		"── urls ──",
		"[Ctrl-C] quit", // console pane bottom border
	}
	for _, s := range mustNotContain {
		if strings.Contains(out, s) {
			t.Errorf("default render must not contain %q; bottom pane should be hidden by default", s)
		}
	}
	// Corner-rune sweep: exactly one of each (single pane fills the screen).
	for _, corner := range []string{"╭", "╮", "╰", "╯"} {
		if got := strings.Count(out, corner); got != 1 {
			t.Errorf("corner %q appears %d time(s) in default render; want 1 (single pane)", corner, got)
		}
	}
}

// TestRender_DefaultState_PanelHotkeysInBorder catches "hotkey
// position regressed back inside the panel header (where it's
// invisible by default)" — the user's directive named the border
// position specifically.
func TestRender_DefaultState_PanelHotkeysInBorder(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()
	for _, want := range []string{"[1]console", "[2]info", "[3]llm", "[4]urls"} {
		if !strings.Contains(out, want) {
			t.Errorf("approvals border missing %q hotkey hint; first 400: %q", want, first(out, 400))
		}
	}
	// The hint must live on the approvals top-border row (the one
	// containing ╭ and ╮ and "operations") — not buried inside a
	// hidden panel header.
	rows := strings.Split(out, "\r\n")
	found := false
	for _, row := range rows {
		if strings.Contains(row, "[1]console") &&
			strings.Contains(row, "╭") && strings.Contains(row, "╮") &&
			strings.Contains(row, "operations") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("panel-hotkey hint not on approvals top-border row")
	}
}

// TestApplyKey_ZeroClosesPanel pins the close-key contract: '0' in
// approvals focus flips BottomPanelOpen from true to false and snaps
// focus back to approvals.
func TestApplyKey_ZeroClosesPanel(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole, // operator had tabbed into the panel
		BottomPanel:     BottomPanelInfo,
		BottomPanelOpen: true,
	}
	// Tab back to approvals so applyKeyApprovals consumes the '0'.
	got, _ := Apply(m, KeyEvent{Key: KeyTab})
	got, _ = Apply(got, KeyEvent{Rune: '0'})
	if got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen should be false after '0'; got true")
	}
	if got.Focused != PaneApprovals {
		t.Errorf("Focused should snap to PaneApprovals after '0'; got %v", got.Focused)
	}
	if got.BottomPanel != BottomPanelInfo {
		t.Errorf("BottomPanel selection should survive a hide; got %d, want %d", got.BottomPanel, BottomPanelInfo)
	}
}

// TestApplyKey_NumberedKeysOpenPanels pins that the numbered hotkeys
// not only switch the selection but also OPEN the panel (the
// pre-reactivation behavior was open by default; the new contract is
// the operator opts in).
func TestApplyKey_NumberedKeysOpenPanels(t *testing.T) {
	cases := []struct {
		key  rune
		want BottomPanel
	}{
		{'1', BottomPanelConsole},
		{'2', BottomPanelInfo},
		{'3', BottomPanelLLM},
		{'4', BottomPanelURLs},
	}
	for _, c := range cases {
		t.Run(string(c.key), func(t *testing.T) {
			m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
			got, _ := Apply(m, KeyEvent{Rune: c.key})
			if got.BottomPanel != c.want {
				t.Errorf("BottomPanel = %d, want %d", got.BottomPanel, c.want)
			}
			if !got.BottomPanelOpen {
				t.Errorf("BottomPanelOpen = false; numbered key must open the panel")
			}
		})
	}
}

// TestApplyKey_NumberedKeysToggleSamePanelClosed pins #76: pressing
// a numeric hotkey whose own panel is already the visible one
// toggles it closed — same result as pressing '0' from that state.
func TestApplyKey_NumberedKeysToggleSamePanelClosed(t *testing.T) {
	cases := []struct {
		key   rune
		panel BottomPanel
	}{
		{'1', BottomPanelConsole},
		{'2', BottomPanelInfo},
		{'3', BottomPanelLLM},
		{'4', BottomPanelURLs},
	}
	for _, c := range cases {
		t.Run(string(c.key), func(t *testing.T) {
			// Focus is on approvals — operator presses the hotkey
			// for the currently-visible panel. (Console-focus
			// behavior is pinned separately by
			// TestApplyKey_NumberedKeysPassThroughInConsoleFocus:
			// digits get typed into the input line, not consumed.)
			m := Model{
				Cols: 100, Rows: 30,
				Focused:         PaneApprovals,
				BottomPanel:     c.panel,
				BottomPanelOpen: true,
			}
			got, cmd := Apply(m, KeyEvent{Rune: c.key})
			if got.BottomPanelOpen {
				t.Errorf("BottomPanelOpen still true after pressing %q on its own panel; want false (toggle close)", c.key)
			}
			if got.Focused != PaneApprovals {
				t.Errorf("Focused = %v after toggle-close; want PaneApprovals (no visible bottom pane)", got.Focused)
			}
			if got.BottomPanel != c.panel {
				t.Errorf("BottomPanel selection should survive the toggle-close; got %d, want %d", got.BottomPanel, c.panel)
			}
			if _, ok := cmd.(CmdNone); !ok {
				t.Errorf("toggle-close emitted Cmd %T; want CmdNone (no refresh side effect)", cmd)
			}
		})
	}
}

// TestApplyKey_OneOpensAndFocusesConsole pins #77: opening the
// console panel via '1' from a closed state auto-focuses the new
// panel so the operator can immediately type.
func TestApplyKey_OneOpensAndFocusesConsole(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	got, _ := Apply(m, KeyEvent{Rune: '1'})
	if !got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen = false after '1'; want true")
	}
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel = %d, want BottomPanelConsole", got.BottomPanel)
	}
	if got.Focused != PaneConsole {
		t.Errorf("Focused = %v after '1' (auto-focus on console panel); want PaneConsole", got.Focused)
	}
}

// TestApplyKey_OneSwitchesAndFocusesConsole pins that switching to
// the console panel from another panel also auto-focuses it.
func TestApplyKey_OneSwitchesAndFocusesConsole(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneApprovals,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
	}
	got, _ := Apply(m, KeyEvent{Rune: '1'})
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel = %d, want BottomPanelConsole after switching from URLs", got.BottomPanel)
	}
	if got.Focused != PaneConsole {
		t.Errorf("Focused = %v after switching to console; want PaneConsole", got.Focused)
	}
}

// TestApplyKey_NonConsoleHotkeysKeepApprovalsFocus pins the
// narrowed reading of #77: '2'/'3'/'4' open their panels but do
// NOT auto-focus PaneConsole, because those panels have no
// interactive input today and focus-on-bottom would break single-
// keystroke '0' and 'q' from the operator's hands.
func TestApplyKey_NonConsoleHotkeysKeepApprovalsFocus(t *testing.T) {
	for _, key := range []rune{'2', '3', '4'} {
		t.Run(string(key), func(t *testing.T) {
			m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
			got, _ := Apply(m, KeyEvent{Rune: key})
			if !got.BottomPanelOpen {
				t.Errorf("BottomPanelOpen = false after %q; want true", key)
			}
			if got.Focused != PaneApprovals {
				t.Errorf("Focused = %v after %q; want PaneApprovals (read-only panel)", got.Focused, key)
			}
		})
	}
}

// TestApplyKey_NumberedKeysSwitchAcrossPanels pins that pressing
// a numeric hotkey while a DIFFERENT panel is open switches to that
// panel; it does not close. Distinct case from #76 toggle.
func TestApplyKey_NumberedKeysSwitchAcrossPanels(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneApprovals,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
	}
	got, _ := Apply(m, KeyEvent{Rune: '1'})
	if !got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen flipped to false on cross-panel switch; want true")
	}
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel = %d, want BottomPanelConsole on '1' from URLs", got.BottomPanel)
	}
}

// TestApplyKey_TabIsNoopWhenPanelClosed pins the new Tab semantics:
// when the bottom pane is hidden, Tab does not move focus (there is
// nothing to focus on).
func TestApplyKey_TabIsNoopWhenPanelClosed(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, BottomPanelOpen: false}
	got, _ := Apply(m, KeyEvent{Key: KeyTab})
	if got.Focused != PaneApprovals {
		t.Errorf("Tab moved focus to %v while panel closed; want PaneApprovals", got.Focused)
	}
}

// TestRender_PanelHeaderCarriesHideHotkey pins that when a panel is
// open, the panel header itself names '[0]hide' so the operator can
// close it without looking back at the approvals border.
func TestRender_PanelHeaderCarriesHideHotkey(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel:     BottomPanelInfo,
		BottomPanelOpen: true,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	if !strings.Contains(b.String(), "[0]hide") {
		t.Errorf("panel header missing [0]hide hotkey; first 600: %q", first(b.String(), 600))
	}
}

// TestRenderURLsPane_SmokeRendersOps pins the URL list panel.
func TestRenderURLsPane_SmokeRendersOps(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "https://api.example.com/v1", Status: "200"},
			{RequestID: "r2", Method: "GET", URL: "https://api.example.com/v1", Status: "200"},
		},
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "urls") {
		t.Errorf("URLs panel missing 'urls' header in output")
	}
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("URLs panel missing URL in output")
	}
}
