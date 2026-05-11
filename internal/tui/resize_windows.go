//go:build windows

package tui

import (
	"context"
	"os"
)

// watchResize on Windows is a no-op: the platform exposes no SIGWINCH-
// equivalent signal in the syscall package, and this layer does not
// poll for size changes. The first paint sizes the model from the
// initial cols/rows passed into runLoop; subsequent terminal resizes
// are not reflected in the TUI until the next layout pass triggered
// by another event. A polling-based resize watcher belongs with the
// broader Windows TUI work tracked separately.
func watchResize(ctx context.Context, out *os.File, events chan<- Event) {
	_ = out
	_ = events
	<-ctx.Done()
}
