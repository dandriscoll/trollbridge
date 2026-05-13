// Package configwatch watches trollbridge.yaml for external edits
// and fires a reload callback (closes #80; fsnotify migration closes
// #110). Editor flows that do an atomic rename-replace (most modern
// editors, including vim's writebackup pattern, VS Code, sed -i) are
// handled by re-establishing the watch on the path's parent directory
// when a RENAME or REMOVE arrives.
//
// The internal configwrite paths (console allow/deny/remove and the
// approvals queue's persist callback) reload in-process directly;
// they call MarkReloaded after their writes so the next event observed
// from disk does not double-fire.
//
// fsnotify replaces the original mtime-polling implementation. The
// switch removes the prior 2s detection floor and the per-tick stat()
// load. If fsnotify cannot initialize on the host (very rare —
// typically resource exhaustion or a non-supported FS), Start falls
// back to mtime polling so the watcher's behavior is preserved.
package configwatch

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultInterval is the polling interval used by the legacy fallback
// path (when fsnotify cannot initialize). Tests can lower it via
// WithInterval.
const DefaultInterval = 2 * time.Second

// fsnotifyDebounce coalesces bursts of events from a single editor
// save (write + chmod + close) into one reload call. Tuned short
// enough that human-perceptible latency stays sub-100ms.
const fsnotifyDebounce = 50 * time.Millisecond

// Watcher tracks the last mtime observed for a single watched path
// and fires a callback when the on-disk content moves past it. Under
// fsnotify, the mtime check is the suppression mechanism for
// MarkReloaded (internal-write coalescing); the event itself is what
// triggers the check.
type Watcher struct {
	mu        sync.Mutex
	path      string
	seenMTime time.Time
	interval  time.Duration
}

// New returns a Watcher bound to the given path. Interval is the
// polling fallback's tick rate; fsnotify is event-driven and ignores
// it. Override via WithInterval.
func New(path string) *Watcher {
	return &Watcher{path: path, interval: DefaultInterval}
}

// WithInterval sets the polling fallback's tick rate. Useful in
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
// reload so the watcher's next event (or poll) observes no change
// and does not redundantly fire (the user's "ignore its own writes"
// point in #80).
func (w *Watcher) MarkReloaded() {
	info, err := os.Stat(w.path)
	if err != nil {
		// File may have been deleted between write and Stat. Leave
		// the prior seenMTime in place; the next existing-file
		// observation will compare against it correctly.
		return
	}
	w.mu.Lock()
	w.seenMTime = info.ModTime()
	w.mu.Unlock()
}

// Start begins the watch loop. fsnotify is the primary mechanism;
// if it cannot initialize, Start falls back to mtime polling. In
// both modes the watcher captures the file's initial mtime so the
// first observation does not fire on day-one state, then triggers
// reload() whenever an external write moves the mtime past seen.
//
// The fsnotify watch is on the file's PARENT DIRECTORY rather than
// the file itself. This is the standard pattern for atomic-rename
// editors (vim writebackup, VS Code, sed -i): when an editor
// rename-replaces the target, the original inode is unlinked and a
// new one appears under the same name. A direct file watch loses
// its target and goes silent; a parent-directory watch keeps firing
// CREATE events for the new inode.
//
// reload runs inside the watcher's goroutine. Callers that need
// concurrent reloads should dispatch internally; this watcher
// serializes its own events against the reload.
func (w *Watcher) Start(ctx context.Context, reload func()) error {
	if info, err := os.Stat(w.path); err == nil {
		w.mu.Lock()
		w.seenMTime = info.ModTime()
		w.mu.Unlock()
	}

	notifier, err := fsnotify.NewWatcher()
	if err != nil {
		return w.startPollLoop(ctx, reload)
	}
	defer notifier.Close()

	dir := filepath.Dir(w.path)
	if err := notifier.Add(dir); err != nil {
		// Fallback: parent directory may not exist yet. Mtime
		// polling tolerates a missing path more gracefully (it
		// just no-ops until the file appears).
		return w.startPollLoop(ctx, reload)
	}

	// Debouncer: coalesce a burst of events from one editor save
	// into a single reload. Reset the timer on every event.
	var (
		debounceMu sync.Mutex
		debounce   *time.Timer
	)
	scheduleReload := func() {
		debounceMu.Lock()
		defer debounceMu.Unlock()
		if debounce != nil {
			debounce.Stop()
		}
		debounce = time.AfterFunc(fsnotifyDebounce, func() {
			w.maybeFireReload(reload)
		})
	}
	defer func() {
		debounceMu.Lock()
		if debounce != nil {
			debounce.Stop()
		}
		debounceMu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-notifier.Events:
			if !ok {
				return nil
			}
			// Filter: only events whose Name matches the watched
			// file. The directory-level watch surfaces events for
			// every entry; we care about exactly one.
			if ev.Name != w.path {
				continue
			}
			// CHMOD-only events on the same inode (e.g. `touch -t`
			// with no content change) do not produce a new mtime
			// after MarkReloaded, so the suppression check below
			// will swallow them. CREATE / WRITE / RENAME are the
			// load-bearing kinds.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
				continue
			}
			scheduleReload()
		case err, ok := <-notifier.Errors:
			if !ok {
				return nil
			}
			// Surface errors as reload signals so a transient ENOSPC
			// or watcher overflow doesn't silently lose updates;
			// maybeFireReload's mtime check still gates the actual
			// callback.
			_ = err
			scheduleReload()
		}
	}
}

// maybeFireReload checks whether the watched file's mtime has
// advanced past seenMTime; if so, updates seenMTime and invokes
// reload. The mtime check is the MarkReloaded suppression layer:
// after an internal write the watcher captures the new mtime as
// seen, so the matching fsnotify event finds nothing to do.
func (w *Watcher) maybeFireReload(reload func()) {
	info, err := os.Stat(w.path)
	if err != nil {
		// File may have been removed (rename-replace mid-flight);
		// the next CREATE event will re-trigger.
		return
	}
	w.mu.Lock()
	same := info.ModTime().Equal(w.seenMTime)
	if !same {
		w.seenMTime = info.ModTime()
	}
	w.mu.Unlock()
	if same {
		return
	}
	reload()
}

// startPollLoop is the legacy mtime-polling implementation, retained
// as a fallback when fsnotify cannot initialize (rare; e.g. inotify
// resource exhaustion on Linux, or filesystems that don't support
// FSEvents on macOS).
func (w *Watcher) startPollLoop(ctx context.Context, reload func()) error {
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
			w.maybeFireReload(reload)
		}
	}
}
