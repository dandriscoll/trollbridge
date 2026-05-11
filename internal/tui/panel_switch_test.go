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
	m := Model{Cols: 100, Rows: 30, Focused: PaneConsole, Console: ConsoleModel{Prompt: "> "}}
	got, _ := Apply(m, KeyEvent{Rune: '3'})
	// Console focus consumes printable runes into the input line.
	if got.BottomPanel != BottomPanelConsole {
		t.Errorf("BottomPanel should not have changed: got %d", got.BottomPanel)
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
		BottomPanel: BottomPanelLLM,
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

// TestRenderURLsPane_SmokeRendersOps pins the URL list panel.
func TestRenderURLsPane_SmokeRendersOps(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		BottomPanel: BottomPanelURLs,
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
