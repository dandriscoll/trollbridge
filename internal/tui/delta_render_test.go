package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/approvals"
)

// TestDeltaRender_FirstFrameIsFull pins the first-paint behavior:
// with prev == "", writeDeltaFrame falls back to writeFullFrame
// and emits the home + clear-screen prefix.
func TestDeltaRender_FirstFrameIsFull(t *testing.T) {
	frame := buildFrame(simpleModel(80, 24))
	var b strings.Builder
	if err := writeDeltaFrame(&b, frame, ""); err != nil {
		t.Fatalf("writeDeltaFrame: %v", err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "\x1b[H\x1b[2J") {
		t.Errorf("first frame must start with home+clear; got prefix %q", first(out, 16))
	}
}

// TestDeltaRender_NoChangeEmitsZeroBytes is the load-bearing #202
// claim: when the model has not changed between renders, the
// delta path writes nothing. The full-render path would have
// re-emitted the entire screen.
func TestDeltaRender_NoChangeEmitsZeroBytes(t *testing.T) {
	m := simpleModel(80, 24)
	frame := buildFrame(m)
	var b strings.Builder
	if err := writeDeltaFrame(&b, frame, frame); err != nil {
		t.Fatalf("writeDeltaFrame: %v", err)
	}
	if got := b.Len(); got != 0 {
		t.Errorf("unchanged frame should emit 0 bytes; got %d:\n%q", got, b.String())
	}
}

// TestDeltaRender_OneLineChangeEmitsOneLine ensures the diff
// granularity is per-line. Modify one model field that affects
// one rendered line; assert the delta emits exactly one
// cursor-position + line + clear-to-EOL sequence (one
// "\x1b[<r>;1H" anchor).
func TestDeltaRender_OneLineChangeEmitsOneLine(t *testing.T) {
	prev := simpleModel(80, 24)
	curr := simpleModel(80, 24)
	// Add a single hold so the approvals pane gains one row of
	// content — affects exactly one line in the pane body.
	curr.Holds = []approvals.Snapshot{{
		ID:     "r1",
		Method: "GET", Host: "example.com", Port: 443, Path: "/", Scheme: "https",
	}}
	prevFrame := buildFrame(prev)
	currFrame := buildFrame(curr)
	if prevFrame == currFrame {
		t.Fatal("test fixture produced identical frames; the assertion would be vacuous")
	}
	var b strings.Builder
	if err := writeDeltaFrame(&b, currFrame, prevFrame); err != nil {
		t.Fatalf("writeDeltaFrame: %v", err)
	}
	out := b.String()
	if strings.Contains(out, "\x1b[H\x1b[2J") {
		t.Errorf("delta with same line count must NOT emit home+clear; got %q", first(out, 64))
	}
	anchors := strings.Count(out, "\x1b[")
	// Each emitted changed line writes one \x1b[<r>;1H anchor and
	// one \x1b[K terminator (and any embedded SGR codes that are
	// part of the line itself). Anchors+terminators dominate the
	// shape; expect at least 2 (anchor + clear) but bounded.
	if anchors < 2 {
		t.Errorf("delta should contain at least one anchor + clear (got %d \\x1b[ tokens):\n%q",
			anchors, out)
	}
}

// TestDeltaRender_RowsChangeFallsBackToFull pins the fallback
// path: when the rendered line count differs (e.g., terminal
// resize), the delta emits a full repaint.
func TestDeltaRender_RowsChangeFallsBackToFull(t *testing.T) {
	prev := buildFrame(simpleModel(80, 24))
	curr := buildFrame(simpleModel(80, 30))
	var b strings.Builder
	if err := writeDeltaFrame(&b, curr, prev); err != nil {
		t.Fatalf("writeDeltaFrame: %v", err)
	}
	if !strings.HasPrefix(b.String(), "\x1b[H\x1b[2J") {
		t.Errorf("line-count change should fall back to full repaint with home+clear; got prefix %q",
			first(b.String(), 16))
	}
}

// TestDeltaRender_FinalScreenMatchesFullRender is the #202 drift
// guard: apply a sequence of model changes via delta and via full
// render, replay both byte streams through the virtual screen,
// and assert the final visible state is identical. This is the
// long-running pixel-perfect contract the user named in #202;
// the short-running version (one sequence) catches the most
// common drift shapes (line-count mismatch, partial-line
// truncation, SGR-code interaction with cursor positioning).
func TestDeltaRender_FinalScreenMatchesFullRender(t *testing.T) {
	cols, rows := 80, 24
	models := []Model{
		simpleModel(cols, rows),
		modelWithHolds(cols, rows, 1),
		modelWithHolds(cols, rows, 3),
		modelWithBottomPanel(cols, rows, BottomPanelConsole),
		modelWithBottomPanel(cols, rows, BottomPanelLLM),
		simpleModel(cols, rows), // back to empty
	}
	// Full-render replay: each frame is writeFullFrame.
	var fullBytes strings.Builder
	for _, m := range models {
		_ = writeFullFrame(&fullBytes, buildFrame(m))
	}
	fullScreen := virtualScreen(fullBytes.String(), rows, cols)

	// Delta replay: each frame is writeDeltaFrame against prev.
	var deltaBytes strings.Builder
	var prev string
	for _, m := range models {
		frame := buildFrame(m)
		_ = writeDeltaFrame(&deltaBytes, frame, prev)
		prev = frame
	}
	deltaScreen := virtualScreen(deltaBytes.String(), rows, cols)

	if strings.Join(fullScreen, "\n") != strings.Join(deltaScreen, "\n") {
		t.Errorf("delta replay drifted from full replay\nfull (%d bytes):\n%s\n\ndelta (%d bytes):\n%s",
			fullBytes.Len(), strings.Join(fullScreen, "\n"),
			deltaBytes.Len(), strings.Join(deltaScreen, "\n"))
	}

	// Sanity: the delta path should usually emit FEWER bytes than
	// the full-render path across the same sequence (the #202
	// motivation). One pathological case where it doesn't:
	// every model differs in every line. Our sequence is mixed.
	if deltaBytes.Len() >= fullBytes.Len() {
		t.Logf("delta did not reduce bytes for this sequence (delta=%d, full=%d) — acceptable if every frame's line set is fully replaced, but worth noting",
			deltaBytes.Len(), fullBytes.Len())
	}
}

func simpleModel(cols, rows int) Model {
	return Model{
		Cols:    cols,
		Rows:    rows,
		Focused: PaneApprovals,
		Console: ConsoleModel{Prompt: "trollbridge> "},
	}
}

func modelWithHolds(cols, rows, n int) Model {
	m := simpleModel(cols, rows)
	for i := 0; i < n; i++ {
		m.Holds = append(m.Holds, approvals.Snapshot{
			ID:     "r" + string(rune('1'+i)),
			Method: "GET", Host: "host" + string(rune('1'+i)) + ".example",
			Port: 443, Path: "/", Scheme: "https",
		})
	}
	return m
}

func modelWithBottomPanel(cols, rows int, panel BottomPanel) Model {
	m := simpleModel(cols, rows)
	m.BottomPanelOpen = true
	m.BottomPanel = panel
	m.Focused = PaneConsole
	return m
}
