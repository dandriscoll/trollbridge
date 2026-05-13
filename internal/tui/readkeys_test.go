package tui

import (
	"context"
	"io"
	"testing"
	"time"
)

// TestReadKeys_TableDriven_BytesToEvents closes the CSI byte parser
// suite bullet from #104. One row per byte sequence the parser is
// expected to recognize; asserts the resulting KeyEvent. The coverage
// pins the readKeys implementation in approvals.go against the silent
// regressions a future contributor introducing a fifth control byte
// could ship.
func TestReadKeys_TableDriven_BytesToEvents(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  KeyEvent
	}{
		{"ctrl_c", []byte{0x03}, KeyEvent{Key: KeyCtrlC}},
		{"tab", []byte{0x09}, KeyEvent{Key: KeyTab}},
		{"enter", []byte{0x0d}, KeyEvent{Key: KeyEnter}},
		{"lf_as_enter", []byte{0x0a}, KeyEvent{Key: KeyEnter}},
		{"backspace_del", []byte{0x7f}, KeyEvent{Key: KeyBackspace}},
		{"backspace_bs", []byte{0x08}, KeyEvent{Key: KeyBackspace}},
		{"ctrl_u", []byte{0x15}, KeyEvent{Key: KeyCtrlU}},
		{"ctrl_z", []byte{0x1a}, KeyEvent{Key: KeyCtrlZ}},
		{"ctrl_l", []byte{0x0c}, KeyEvent{Key: KeyCtrlL}},
		{"esc_alone", []byte{0x1b}, KeyEvent{Key: KeyEsc}},
		{"csi_up", []byte{0x1b, '[', 'A'}, KeyEvent{Key: KeyUp}},
		{"csi_down", []byte{0x1b, '[', 'B'}, KeyEvent{Key: KeyDown}},
		{"csi_shift_tab", []byte{0x1b, '[', 'Z'}, KeyEvent{Key: KeyShiftTab}},
		{"csi_delete", []byte{0x1b, '[', '3', '~'}, KeyEvent{Key: KeyDelete}},
		{"printable_a", []byte{'a'}, KeyEvent{Rune: 'a'}},
		{"printable_zero", []byte{'0'}, KeyEvent{Rune: '0'}},
		{"printable_space", []byte{' '}, KeyEvent{Rune: ' '}},
		{"printable_tilde", []byte{'~'}, KeyEvent{Rune: '~'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pr.Close()
			ev := make(chan Event, 4)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go readKeys(ctx, pr, ev)

			if _, err := pw.Write(tc.input); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-ev:
				ke, ok := got.(KeyEvent)
				if !ok {
					t.Fatalf("event type: got %T, want KeyEvent", got)
				}
				if ke != tc.want {
					t.Errorf("event: got %+v, want %+v", ke, tc.want)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("readKeys produced no event for %x within 500ms", tc.input)
			}
			pw.Close()
		})
	}
}
