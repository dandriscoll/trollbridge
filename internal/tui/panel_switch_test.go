package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
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
	// Start with the console panel open and focused so console-input
	// behavior is what we exercise. (Previously this test used the
	// URLs panel as a generic "some panel open" state; after #79
	// the URLs panel routes keys to applyKeyURLs, not applyKeyConsole,
	// so the test now uses the console panel explicitly.)
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelConsole,
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
// narrowed reading of #77: '2' opens the info panel but does NOT
// auto-focus PaneConsole, because that panel has no interactive
// input and focus-on-bottom would break single-keystroke '0' and
// 'q' from the operator's hands.
//
// '3' (LLM) was previously in this set; #81 makes the LLM panel
// interactively browseable (up/down navigation + detail
// expansion), so it now auto-focuses on '3' — see
// TestApplyKey_ThreeOpensAndFocusesLLM.
//
// '4' (URLs) is also excluded: #79 makes the URLs pane editable,
// so it gets auto-focus. See TestApplyKey_FourOpensAndFocusesURLs.
func TestApplyKey_NonConsoleHotkeysKeepApprovalsFocus(t *testing.T) {
	for _, key := range []rune{'2'} {
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

// TestRenderURLsPane_RendersAllowDenyLists pins #79: the URLs
// panel shows the allow/deny lists from trollbridge.yaml with
// labeled sections, not the ops-ring roll-up.
func TestRenderURLsPane_RendersAllowDenyLists(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       []string{"api.example.com", "*.trusted.org"},
		DenyList:        []string{"evil.example", "tracking.adnetwork.example"},
		URLsSelected:    -1,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()
	for _, want := range []string{"urls", "ALLOW (2)", "DENY (2)", "api.example.com", "*.trusted.org", "evil.example", "tracking.adnetwork.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("URLs panel missing %q in output", want)
		}
	}
}

// TestRenderURLsPane_AttachModeShowsHint pins that when
// URLsLocal=false (attach mode) the pane shows the proxy-host
// hint instead of empty list contents.
func TestRenderURLsPane_AttachModeShowsHint(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       false,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render error: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "runs on the proxy host") {
		t.Errorf("attach-mode hint missing in URLs pane; first 600: %q", first(out, 600))
	}
}

// TestApplyKey_FourOpensAndFocusesURLs pins that '4' both opens
// the URLs pane AND auto-focuses it (#79 makes the pane editable,
// so auto-focus is part of the contract; see Job 129's research
// for why '2'/'3' do not auto-focus).
func TestApplyKey_FourOpensAndFocusesURLs(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	got, cmd := Apply(m, KeyEvent{Rune: '4'})
	if got.BottomPanel != BottomPanelURLs {
		t.Errorf("BottomPanel = %d, want BottomPanelURLs", got.BottomPanel)
	}
	if !got.BottomPanelOpen {
		t.Errorf("BottomPanelOpen = false; want true")
	}
	if got.Focused != PaneConsole {
		t.Errorf("Focused = %v after '4'; want PaneConsole (auto-focus for editable pane)", got.Focused)
	}
	if _, ok := cmd.(CmdURLsRefresh); !ok {
		t.Errorf("Cmd = %T; want CmdURLsRefresh on '4' open", cmd)
	}
}

// TestApplyKeyURLs_NavigatesAcrossAllowDeny pins j/k movement
// across the allow→deny boundary. Selection is an index into the
// combined list (allow first, then deny).
func TestApplyKeyURLs_NavigatesAcrossAllowDeny(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       []string{"a.example", "b.example"},
		DenyList:        []string{"d.example"},
		URLsSelected:    0,
	}
	// 'j' four times — past the end of the combined list.
	got := m
	for i := 0; i < 4; i++ {
		got, _ = Apply(got, KeyEvent{Rune: 'j'})
	}
	if got.URLsSelected != 2 {
		t.Errorf("URLsSelected after 4×j = %d, want 2 (clamped to last entry)", got.URLsSelected)
	}
	// 'k' three times — back across allow→deny boundary.
	for i := 0; i < 3; i++ {
		got, _ = Apply(got, KeyEvent{Rune: 'k'})
	}
	if got.URLsSelected != 0 {
		t.Errorf("URLsSelected after 4×j+3×k = %d, want 0", got.URLsSelected)
	}
}

// TestApplyKeyURLs_XRemovesSelected pins that 'x' on the selected
// entry emits a CmdConsoleExec{Line: "remove <pattern>"} so the
// existing configwrite path runs. The pattern picked from the
// combined index — allow entries first, then deny.
func TestApplyKeyURLs_XRemovesSelected(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       []string{"a.example", "b.example"},
		DenyList:        []string{"d.example"},
		URLsSelected:    2, // index 2 = first deny entry
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'x'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("Cmd = %T; want CmdConsoleExec", cmd)
	}
	if exec.Line != "remove d.example" {
		t.Errorf("Cmd.Line = %q, want %q", exec.Line, "remove d.example")
	}
	_ = got
}

// TestApplyKeyURLs_XInAttachModeIsRefused pins that 'x' produces
// a clear error rather than silently no-opping when the URLs pane
// is read-only (attach mode).
func TestApplyKeyURLs_XInAttachModeIsRefused(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       false,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'x'})
	if _, ok := cmd.(CmdNone); !ok {
		t.Errorf("Cmd = %T; want CmdNone in attach mode", cmd)
	}
	if got.LastErr == "" {
		t.Errorf("LastErr empty in attach mode; want a refusal hint")
	}
}

// TestApplyKeyURLs_EscDefocuses pins that Esc inside the URLs pane
// returns focus to approvals (same convention as console pane Esc).
func TestApplyKeyURLs_EscDefocuses(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.Focused != PaneApprovals {
		t.Errorf("Focused after Esc = %v; want PaneApprovals", got.Focused)
	}
}

// TestApplyURLsTickResult_UpdatesModel pins the event handler:
// the tick populates AllowList/DenyList/URLsLocal and clamps
// URLsSelected to the new combined length.
func TestApplyURLsTickResult_UpdatesModel(t *testing.T) {
	m := Model{URLsSelected: 5}
	got, _ := Apply(m, URLsTickResult{
		Allow: []string{"a.example"},
		Deny:  []string{"d.example"},
		Local: true,
	})
	if !got.URLsLocal {
		t.Errorf("URLsLocal = false; want true")
	}
	if len(got.AllowList) != 1 || got.AllowList[0] != "a.example" {
		t.Errorf("AllowList = %v, want [a.example]", got.AllowList)
	}
	if len(got.DenyList) != 1 || got.DenyList[0] != "d.example" {
		t.Errorf("DenyList = %v, want [d.example]", got.DenyList)
	}
	if got.URLsSelected != 1 {
		t.Errorf("URLsSelected = %d after clamp to 2-entry list; want 1", got.URLsSelected)
	}
}

// TestApplyConsoleExec_RefreshesURLsWhenURLsPaneOpen pins that
// after any console exec while the URLs pane is open, a refresh
// fires so the operator sees the post-mutation list state.
func TestApplyConsoleExec_RefreshesURLsWhenURLsPaneOpen(t *testing.T) {
	m := Model{
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
	}
	_, cmd := Apply(m, ConsoleExecResult{Line: "remove x.example", Output: "removed x.example from allow\n"})
	if _, ok := cmd.(CmdURLsRefresh); !ok {
		t.Errorf("Cmd = %T; want CmdURLsRefresh after console exec with URLs pane open", cmd)
	}
}

// TestApplyKey_DigitPassthroughFromURLs closes #98 part 4: the
// URLs-panel handler must let '0'-'4' meta-keys switch panels.
// Pre-fix, those digits fell through to the URLs handler's
// default-no-op return.
func TestApplyKey_DigitPassthroughFromURLs(t *testing.T) {
	m := Model{
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelURLs,
		Focused:         PaneConsole,
		URLsLocal:       true,
	}
	// '3' from URLs focus must switch to LLM.
	got, _ := Apply(m, KeyEvent{Rune: '3'})
	if got.BottomPanel != BottomPanelLLM {
		t.Errorf("BottomPanel after '3' from URLs: got %v, want LLM", got.BottomPanel)
	}
	// '0' from URLs focus must close the panel.
	got2, _ := Apply(m, KeyEvent{Rune: '0'})
	if got2.BottomPanelOpen {
		t.Errorf("BottomPanelOpen after '0' from URLs: got true, want false")
	}
}

// TestApplyKey_DigitPassthroughFromLLM is the sibling assertion for
// the LLM-panel handler.
func TestApplyKey_DigitPassthroughFromLLM(t *testing.T) {
	m := Model{
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelLLM,
		Focused:         PaneConsole,
	}
	// '4' from LLM focus must switch to URLs.
	got, _ := Apply(m, KeyEvent{Rune: '4'})
	if got.BottomPanel != BottomPanelURLs {
		t.Errorf("BottomPanel after '4' from LLM: got %v, want URLs", got.BottomPanel)
	}
	// '1' from LLM focus must switch to Console.
	got2, _ := Apply(m, KeyEvent{Rune: '1'})
	if got2.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel after '1' from LLM: got %v, want Console", got2.BottomPanel)
	}
}

// TestApplyKey_DispatchTableRoutesPerPanel closes #98 part 1: the
// new map-based dispatch routes URLs and LLM keys to their
// per-panel handlers. We assert by issuing a key the per-panel
// handler interprets distinctly (j cursor-down on URLs, j cursor-
// down on LLM).
func TestApplyKey_DispatchTableRoutesPerPanel(t *testing.T) {
	m := Model{
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelURLs,
		Focused:         PaneConsole,
		AllowList:       []string{"a", "b"},
		URLsSelected:    0,
	}
	got, _ := Apply(m, KeyEvent{Rune: 'j'})
	if got.URLsSelected != 1 {
		t.Errorf("URLs handler did not receive 'j': URLsSelected=%d, want 1", got.URLsSelected)
	}
}
