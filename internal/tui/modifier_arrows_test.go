package tui

import (
	"context"
	"io"
	"testing"
	"time"
)

// drainEvents collects every KeyEvent readKeys emits for a byte
// sequence until the channel goes quiet for the idle window. It is the
// load-bearing harness for the modifier-arrow leak: the bug is not "the
// first event is wrong" but "extra rune events leak after it", so the
// assertion must see the full event sequence, not just the head.
func drainEvents(t *testing.T, input []byte) []KeyEvent {
	t.Helper()
	pr, pw := io.Pipe()
	defer pr.Close()
	ev := make(chan Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go readKeys(ctx, pr, ev)
	if _, err := pw.Write(input); err != nil {
		t.Fatal(err)
	}
	var got []KeyEvent
	idle := time.NewTimer(150 * time.Millisecond)
	defer idle.Stop()
	for {
		select {
		case e := <-ev:
			ke, ok := e.(KeyEvent)
			if !ok {
				t.Fatalf("event type: got %T, want KeyEvent", e)
			}
			got = append(got, ke)
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(150 * time.Millisecond)
		case <-idle.C:
			pw.Close()
			return got
		}
	}
}

// TestReadKeys_ModifierArrows_NoRuneLeak pins #171 bug 1: a modifier
// CSI sequence (Shift-Up = ESC [ 1 ; 2 A, as emitted by xterm/tmux)
// must produce exactly one key event and leak no printable runes. The
// pre-fix parser consumed `ESC [ 1`, matched no case, and leaked
// `;`, `2`, `A` as runes — the `2` opened the info panel.
func TestReadKeys_ModifierArrows_NoRuneLeak(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  []KeyEvent
	}{
		{"shift_up", []byte{0x1b, '[', '1', ';', '2', 'A'}, []KeyEvent{{Key: KeyShiftUp}}},
		{"shift_down", []byte{0x1b, '[', '1', ';', '2', 'B'}, []KeyEvent{{Key: KeyShiftDown}}},
		{"ctrl_up_degrades_to_up", []byte{0x1b, '[', '1', ';', '5', 'A'}, []KeyEvent{{Key: KeyUp}}},
		{"alt_down_degrades_to_down", []byte{0x1b, '[', '1', ';', '3', 'B'}, []KeyEvent{{Key: KeyDown}}},
		// Pre-existing forms must still parse and still not leak.
		{"plain_up", []byte{0x1b, '[', 'A'}, []KeyEvent{{Key: KeyUp}}},
		{"plain_down", []byte{0x1b, '[', 'B'}, []KeyEvent{{Key: KeyDown}}},
		{"shift_tab", []byte{0x1b, '[', 'Z'}, []KeyEvent{{Key: KeyShiftTab}}},
		{"delete", []byte{0x1b, '[', '3', '~'}, []KeyEvent{{Key: KeyDelete}}},
		{"esc_alone", []byte{0x1b}, []KeyEvent{{Key: KeyEsc}}},
		// Unknown CSI (Home = ESC [ H) is swallowed, not leaked.
		{"home_swallowed", []byte{0x1b, '[', 'H'}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := drainEvents(t, tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("event count: got %+v, want %+v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("event[%d]: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
