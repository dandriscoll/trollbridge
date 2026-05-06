package hostlist

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcher_FiresOnFileWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte("a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls int32
	w := NewWatcher([]string{p}, func() { atomic.AddInt32(&calls, 1) }, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	// Wait a tick then modify the file. mtime granularity on some
	// filesystems is 1 second, so make sure both write and stat
	// see distinct timestamps by sleeping ~1.1s before the write.
	time.Sleep(100 * time.Millisecond)
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(p, []byte("a.example\nb.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("watcher did not fire within deadline")
}

func TestWatcher_NoCallbackWithoutChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte("a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int32
	w := NewWatcher([]string{p}, func() { atomic.AddInt32(&calls, 1) }, 30*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("watcher fired without a change: %d", calls)
	}
}

func TestWatcher_HandlesMissingFileWithoutPanic(t *testing.T) {
	w := NewWatcher([]string{"/no/such/path"}, func() {}, 30*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	defer w.Stop()
	time.Sleep(100 * time.Millisecond)
	// no panic ⇒ pass
}

func TestWatcher_EmptyPathsIsNoop(t *testing.T) {
	w := NewWatcher(nil, func() { t.Error("should not fire") }, 30*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
}
