// Package configwatch polls trollbridge.yaml's mtime and fires a
// reload callback when an external edit lands (closes #80).
//
// The internal configwrite paths (console allow/deny/remove and the
// approvals queue's persist callback) reload in-process directly;
// they call MarkReloaded after their writes so the next poll
// observes no change and the watcher does not double-fire.
//
// Polling rather than fsnotify keeps the dependency surface flat;
// 2s latency is acceptable for a user-driven edit-then-watch flow.
// A future job can migrate to fsnotify if event-driven detection
// becomes necessary.
package configwatch

import (
	"context"
	"os"
	"sync"
	"time"
)

// DefaultInterval is how often Start polls os.Stat(path).ModTime().
// Tests can lower it via WithInterval.
const DefaultInterval = 2 * time.Second

// Watcher tracks the last mtime observed for a single watched path
// and fires a callback when the on-disk mtime moves past it.
type Watcher struct {
	mu        sync.Mutex
	path      string
	seenMTime time.Time
	interval  time.Duration
}

// New returns a Watcher bound to the given path. Interval defaults
// to DefaultInterval; override via WithInterval.
func New(path string) *Watcher {
	return &Watcher{path: path, interval: DefaultInterval}
}

// WithInterval returns w with its poll interval set to d. Useful in
// tests; production callers leave the default.
func (w *Watcher) WithInterval(d time.Duration) *Watcher {
	w.mu.Lock()
	defer w.mu.Unlock()
	if d > 0 {
		w.interval = d
	}
	return w
}

// MarkReloaded records the watched file's current mtime as "seen."
// Internal configwrite paths call this after their in-process
// reload so the watcher's next poll observes no change and does
// not redundantly fire (the user's "ignore its own writes" point
// in #80).
func (w *Watcher) MarkReloaded() {
	info, err := os.Stat(w.path)
	if err != nil {
		// File may have been deleted between write and Stat. Leave
		// the prior seenMTime in place; the next existing-file poll
		// will compare against it correctly.
		return
	}
	w.mu.Lock()
	w.seenMTime = info.ModTime()
	w.mu.Unlock()
}

// Start begins the poll loop. It captures the file's initial mtime
// (so the first poll doesn't fire on day-one state) and then ticks
// at the configured interval. On a detected change the watcher
// invokes reload() and updates seenMTime. Returns when ctx is
// cancelled.
//
// reload runs inside the watcher's goroutine. Callers that need
// concurrent reloads should dispatch internally; this watcher
// serializes its own ticks against the reload.
func (w *Watcher) Start(ctx context.Context, reload func()) error {
	if info, err := os.Stat(w.path); err == nil {
		w.mu.Lock()
		w.seenMTime = info.ModTime()
		w.mu.Unlock()
	}
	interval := w.interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			info, err := os.Stat(w.path)
			if err != nil {
				continue
			}
			w.mu.Lock()
			same := info.ModTime().Equal(w.seenMTime)
			if !same {
				w.seenMTime = info.ModTime()
			}
			w.mu.Unlock()
			if same {
				continue
			}
			reload()
		}
	}
}
