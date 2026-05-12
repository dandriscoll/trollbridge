package tui

import (
	"context"
	"io"
	"testing"
	"time"
)

// TestApplyKey_ShiftTabBehavesAsTab pins #83: Shift-Tab toggles
// focus between PaneApprovals and PaneConsole identically to Tab in
// today's two-pane focus model. When the bottom panel is closed,
// Shift-Tab is a no-op (same as Tab).
func TestApplyKey_ShiftTabBehavesAsTab(t *testing.T) {
	cases := []struct {
		name        string
		open        bool
		startFocus  Pane
		wantFocus   Pane
		description string
	}{
		{"closed panel, starts approvals", false, PaneApprovals, PaneApprovals, "no-op when panel closed"},
		{"closed panel, starts console", false, PaneConsole, PaneConsole, "no-op when panel closed"},
		{"open panel, starts approvals", true, PaneApprovals, PaneConsole, "toggles to console"},
		{"open panel, starts console", true, PaneConsole, PaneApprovals, "toggles to approvals"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{
				Cols: 100, Rows: 30,
				Focused:         tc.startFocus,
				BottomPanel:     BottomPanelConsole,
				BottomPanelOpen: tc.open,
			}
			got, _ := Apply(m, KeyEvent{Key: KeyShiftTab})
			if got.Focused != tc.wantFocus {
				t.Errorf("%s: Focused = %v, want %v", tc.description, got.Focused, tc.wantFocus)
			}
		})
	}
}

// TestReadKeys_ShiftTabBytesEmitKeyShiftTab pins the byte-level
// parser: ESC [ Z is the xterm Shift-Tab sequence and must produce
// a KeyEvent{Key: KeyShiftTab}.
func TestReadKeys_ShiftTabBytesEmitKeyShiftTab(t *testing.T) {
	// Build a reader that yields exactly the Shift-Tab CSI bytes,
	// then EOF.
	r, w := io.Pipe()
	go func() {
		_, _ = w.Write([]byte{0x1b, '[', 'Z'})
		_ = w.Close()
	}()

	events := make(chan Event, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go readKeys(ctx, r, events)

	select {
	case ev := <-events:
		ke, ok := ev.(KeyEvent)
		if !ok {
			t.Fatalf("expected KeyEvent, got %T", ev)
		}
		if ke.Key != KeyShiftTab {
			t.Errorf("expected KeyShiftTab, got Key=%v Rune=%q", ke.Key, ke.Rune)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for KeyEvent")
	}
}

// TestReadKeys_TabByteStillEmitsKeyTab pins that the existing Tab
// byte handling is not broken by adding Shift-Tab to the CSI parser.
func TestReadKeys_TabByteStillEmitsKeyTab(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		_, _ = w.Write([]byte{0x09})
		_ = w.Close()
	}()

	events := make(chan Event, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go readKeys(ctx, r, events)

	select {
	case ev := <-events:
		ke, ok := ev.(KeyEvent)
		if !ok {
			t.Fatalf("expected KeyEvent, got %T", ev)
		}
		if ke.Key != KeyTab {
			t.Errorf("expected KeyTab, got Key=%v", ke.Key)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for KeyEvent")
	}
}
