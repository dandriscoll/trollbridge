//go:build !windows

package tui

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchResize emits a ResizeEvent on every SIGWINCH.
func watchResize(ctx context.Context, out *os.File, events chan<- Event) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			emitResize(ctx, out, events)
		}
	}
}
