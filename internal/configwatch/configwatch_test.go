package configwatch

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writeFile(t *testing.T, p string, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWatcher_FiresOnExternalEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	writeFile(t, path, "v1\n")

	w := New(path).WithInterval(20 * time.Millisecond)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	// Ensure the watcher has captured the initial mtime.
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("watcher fired %d times on startup; want 0 (initial mtime captured)", got)
	}

	// Filesystem mtimes have coarse granularity on some platforms;
	// sleep enough to ensure the next write registers a distinct
	// mtime.
	time.Sleep(20 * time.Millisecond)
	writeFile(t, path, "v2\n")

	// Wait for at least one poll cycle plus margin.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatalf("watcher did not fire after external write")
	}
}

func TestWatcher_MarkReloadedSuppressesNextPoll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	writeFile(t, path, "v1\n")

	w := New(path).WithInterval(20 * time.Millisecond)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	time.Sleep(50 * time.Millisecond)

	// Simulate an internal configwrite: the file changes on disk,
	// but the host code reloads in-process AND calls MarkReloaded.
	time.Sleep(20 * time.Millisecond)
	writeFile(t, path, "v2\n")
	w.MarkReloaded()

	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("watcher fired %d times after MarkReloaded; want 0 (internal write suppressed)", got)
	}
}

func TestWatcher_StartReturnsOnCtxCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	writeFile(t, path, "v1\n")

	w := New(path).WithInterval(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = w.Start(ctx, func() {})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("watcher did not exit on ctx cancel")
	}
}

func TestWatcher_MissingFileNoOps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.yaml")

	w := New(path).WithInterval(10 * time.Millisecond)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	time.Sleep(80 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("watcher fired %d times for missing file; want 0", got)
	}
}

func TestWatcher_FileAppearsAfterStart_TriggersReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")

	w := New(path).WithInterval(10 * time.Millisecond)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	time.Sleep(50 * time.Millisecond)
	writeFile(t, path, "fresh\n")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatalf("watcher did not fire after file appeared")
	}
}

// TestWatcher_FsnotifySubSecondDetection asserts the post-#110 win:
// fsnotify-driven detection fires within ~150ms (debounce window +
// scheduling slack), well under the prior 2s mtime-poll floor.
func TestWatcher_FsnotifySubSecondDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	writeFile(t, path, "v1\n")

	w := New(path) // default interval (irrelevant under fsnotify)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	// Let fsnotify's parent-dir watch attach.
	time.Sleep(80 * time.Millisecond)
	// Bump mtime past coarse-granularity floor on macOS HFS+ (~1s).
	time.Sleep(1100 * time.Millisecond)
	start := time.Now()
	writeFile(t, path, "v2\n")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatalf("fsnotify did not fire within 500ms of write")
	}
	elapsed := time.Since(start)
	if elapsed > 400*time.Millisecond {
		t.Errorf("fsnotify detection took %v; want < 400ms (sub-second target)", elapsed)
	}
}

// TestWatcher_AtomicRenameReplace asserts the parent-dir watch
// pattern catches editor rename-replace flows (vim writebackup,
// VS Code, sed -i) that a direct file watch would miss.
func TestWatcher_AtomicRenameReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge.yaml")
	writeFile(t, path, "v1\n")

	w := New(path)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx, func() { calls.Add(1) })

	time.Sleep(80 * time.Millisecond)
	time.Sleep(1100 * time.Millisecond)

	// Atomic write: write to a sibling, then rename over the target.
	tmp := path + ".new"
	writeFile(t, tmp, "v2\n")
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatalf("watcher did not fire after atomic rename-replace")
	}
}
