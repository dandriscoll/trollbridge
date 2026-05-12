package tui

import (
	"fmt"
	"strings"
	"testing"
)

// TestUrlsScrollOffset_BasicBehavior pins the centred-cursor scroll
// rule (closes #84): the visible window slides so the cursor sits
// near the middle, clamped at the start and end of the list.
func TestUrlsScrollOffset_BasicBehavior(t *testing.T) {
	cases := []struct {
		name             string
		cursor, body, n  int
		wantFirstVisible int
	}{
		{"short list, no scroll", 0, 10, 5, 0},
		{"cursor at start, long list", 0, 10, 100, 0},
		{"cursor middle, long list", 50, 10, 100, 45},
		{"cursor near end, long list", 95, 10, 100, 90},
		{"cursor at last, long list", 99, 10, 100, 90},
		{"bodyRows >= total", 50, 100, 50, 0},
		{"bodyRows zero", 5, 0, 100, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := urlsScrollOffset(tc.cursor, tc.body, tc.n)
			if got != tc.wantFirstVisible {
				t.Errorf("urlsScrollOffset(cursor=%d, body=%d, n=%d) = %d, want %d",
					tc.cursor, tc.body, tc.n, got, tc.wantFirstVisible)
			}
		})
	}
}

// TestRenderURLsPane_ScrollsToKeepCursorVisible: with a long allow
// list whose total exceeds the visible body rows, the renderer
// emits the selected entry (cursor visible) and not the first
// entry (scrolled past).
func TestRenderURLsPane_ScrollsToKeepCursorVisible(t *testing.T) {
	allow := make([]string, 50)
	for i := range allow {
		allow[i] = fmt.Sprintf("entry-%02d.example.com", i)
	}
	// Cursor near the end of the list; visible body small enough
	// to force scrolling.
	m := Model{
		Cols: 100, Rows: 12,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       allow,
		URLsSelected:    40,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "entry-40.example.com") {
		t.Errorf("rendered output missing the selected entry (entry-40); should be visible")
	}
	if strings.Contains(out, "entry-00.example.com") {
		t.Errorf("rendered output contains first entry (entry-00); should have scrolled past it")
	}
	if !strings.Contains(out, "\x1b[7m") {
		t.Errorf("rendered output missing the inverse-video selection escape")
	}
}

// TestRenderURLsPane_HeaderAlwaysOnFirstRow: scrolling never
// displaces the panel header line.
func TestRenderURLsPane_HeaderAlwaysOnFirstRow(t *testing.T) {
	allow := make([]string, 30)
	for i := range allow {
		allow[i] = fmt.Sprintf("entry-%02d.example.com", i)
	}
	m := Model{
		Cols: 100, Rows: 12,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       allow,
		URLsSelected:    25,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	// The panel chrome carries the "urls" label in the top border
	// (#88). It must appear regardless of cursor position.
	if !strings.Contains(b.String(), "urls") {
		t.Errorf("panel header missing after scroll; first 600: %q", first(b.String(), 600))
	}
}

// TestRenderURLsPane_ShortListRendersUnchanged: when the entire
// list fits in the visible body, the renderer emits everything —
// no regression from the pre-scroll behavior.
func TestRenderURLsPane_ShortListRendersUnchanged(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		AllowList:       []string{"alpha.example", "beta.example"},
		DenyList:        []string{"evil.example"},
		URLsSelected:    0,
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"ALLOW (2)", "alpha.example", "beta.example", "DENY (1)", "evil.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("short-list render missing %q", want)
		}
	}
}
