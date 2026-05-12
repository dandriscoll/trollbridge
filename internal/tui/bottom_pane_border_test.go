package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// renderModel returns a Model with the bottom panel open at the
// given panel and focus, sized at a comfortable 100x30, used by the
// border-presence tests below.
func renderModel(panel BottomPanel, focus Pane) Model {
	return Model{
		Cols: 100, Rows: 30,
		Focused:         focus,
		BottomPanel:     panel,
		BottomPanelOpen: true,
		URLsLocal:       true,
	}
}

func cornerCount(s string) (top, bot int) {
	top = strings.Count(s, "╭") + strings.Count(s, "╮")
	bot = strings.Count(s, "╰") + strings.Count(s, "╯")
	return
}

// TestRenderInfoPane_HasBorderAndFocusColor pins that the info pane
// now draws a top + bottom border (closes #88) and uses bright-cyan
// chrome when focused, dim grey otherwise.
func TestRenderInfoPane_HasBorderAndFocusColor(t *testing.T) {
	for _, c := range []struct {
		name      string
		focus     Pane
		wantColor string
	}{
		{"focused", PaneConsole, "\x1b[36m"},
		{"unfocused", PaneApprovals, "\x1b[2m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := renderModel(BottomPanelInfo, c.focus)
			var b strings.Builder
			if err := render(&b, m); err != nil {
				t.Fatalf("render: %v", err)
			}
			out := b.String()
			top, bot := cornerCount(out)
			// Both panes get borders — top pane has 2 top corners + 2
			// bottom; bottom pane adds 2 + 2 = 4 each.
			if top < 4 || bot < 4 {
				t.Errorf("expected info pane to add top+bottom corners; got top=%d bot=%d", top, bot)
			}
			if !strings.Contains(out, c.wantColor) {
				t.Errorf("info pane render missing focus color %q", c.wantColor)
			}
		})
	}
}

// TestRenderLLMPane_HasBorderAndFocusColor mirrors the info test
// for the LLM pane.
func TestRenderLLMPane_HasBorderAndFocusColor(t *testing.T) {
	for _, c := range []struct {
		name      string
		focus     Pane
		wantColor string
	}{
		{"focused", PaneConsole, "\x1b[36m"},
		{"unfocused", PaneApprovals, "\x1b[2m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := renderModel(BottomPanelLLM, c.focus)
			m.Digests = []advisor.Digest{
				{
					Timestamp: time.Unix(1_700_000_000, 0).UTC(),
					Effect:    "allow", Confidence: "high",
					Host: "api.example.com", Reason: "test",
				},
			}
			var b strings.Builder
			if err := render(&b, m); err != nil {
				t.Fatalf("render: %v", err)
			}
			out := b.String()
			top, bot := cornerCount(out)
			if top < 4 || bot < 4 {
				t.Errorf("expected LLM pane to add top+bottom corners; got top=%d bot=%d", top, bot)
			}
			if !strings.Contains(out, c.wantColor) {
				t.Errorf("LLM pane render missing focus color %q", c.wantColor)
			}
		})
	}
}

// TestRenderURLsPane_HasBorderAndFocusColor mirrors for URLs.
func TestRenderURLsPane_HasBorderAndFocusColor(t *testing.T) {
	for _, c := range []struct {
		name      string
		focus     Pane
		wantColor string
	}{
		{"focused", PaneConsole, "\x1b[36m"},
		{"unfocused", PaneApprovals, "\x1b[2m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := renderModel(BottomPanelURLs, c.focus)
			m.AllowList = []string{"alpha.example", "beta.example"}
			var b strings.Builder
			if err := render(&b, m); err != nil {
				t.Fatalf("render: %v", err)
			}
			out := b.String()
			top, bot := cornerCount(out)
			if top < 4 || bot < 4 {
				t.Errorf("expected URLs pane to add top+bottom corners; got top=%d bot=%d", top, bot)
			}
			if !strings.Contains(out, c.wantColor) {
				t.Errorf("URLs pane render missing focus color %q", c.wantColor)
			}
		})
	}
}
