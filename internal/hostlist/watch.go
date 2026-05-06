package hostlist

import (
	"context"
	"os"
	"sync"
	"time"
)

// Watcher polls a set of files' mtime+size and calls a callback
// when any of them change. Polling-based; no fsnotify dep.
type Watcher struct {
	paths    []string
	interval time.Duration
	onChange func()

	mu     sync.Mutex
	stamps map[string]fileStamp

	cancel context.CancelFunc
	done   chan struct{}
}

type fileStamp struct {
	mtime time.Time
	size  int64
	miss  bool // file did not exist at last poll
}

// NewWatcher returns a Watcher for the supplied file paths. The
// callback is invoked on a separate goroutine when any watched
// file's mtime or size changes (or transitions present↔missing).
// Empty `paths` produces a no-op watcher whose Start/Stop are
// safe.
func NewWatcher(paths []string, onChange func(), interval time.Duration) *Watcher {
	if interval <= 0 {
		interval = time.Second
	}
	return &Watcher{
		paths:    append([]string(nil), paths...),
		interval: interval,
		onChange: onChange,
		stamps:   map[string]fileStamp{},
	}
}

// Start begins the polling loop. Blocks until ctx is cancelled or
// Stop is called.
func (w *Watcher) Start(ctx context.Context) {
	if len(w.paths) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})
	w.bootstrap()
	go w.loop(ctx)
}

// Stop cancels the poll loop and blocks until it exits.
func (w *Watcher) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *Watcher) bootstrap() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.paths {
		w.stamps[p] = stampOf(p)
	}
}

func (w *Watcher) loop(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if w.poll() {
				if w.onChange != nil {
					w.onChange()
				}
			}
		}
	}
}

// poll returns true if any file changed since the last observation.
func (w *Watcher) poll() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := false
	for _, p := range w.paths {
		next := stampOf(p)
		prev := w.stamps[p]
		if next != prev {
			changed = true
			w.stamps[p] = next
		}
	}
	return changed
}

func stampOf(path string) fileStamp {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{miss: true}
	}
	return fileStamp{mtime: info.ModTime(), size: info.Size()}
}
