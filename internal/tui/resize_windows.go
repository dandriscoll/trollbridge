//go:build windows

package tui

import (
	"context"
	"os"
	"time"

	"golang.org/x/term"
)

// watchResize on Windows polls the terminal size at a 750 ms cadence
// (there is no SIGWINCH-equivalent on Windows). A ResizeEvent fires
// only when the size actually changes, so quiescent terminals do
// not generate event traffic (closes #61).
func watchResize(ctx context.Context, out *os.File, events chan<- Event) {
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	lastCols, lastRows, _ := term.GetSize(int(out.Fd()))
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cols, rows, _ := term.GetSize(int(out.Fd()))
			if cols == 0 || rows == 0 {
				continue
			}
			if cols == lastCols && rows == lastRows {
				continue
			}
			lastCols, lastRows = cols, rows
			emitResize(ctx, out, events)
		}
	}
}
