package opstream

import (
	"sync"
	"testing"
	"time"
)

// fixedClock returns a clock that advances by the configured delta on
// each call. Lets tests pin UpdatedAt ordering deterministically.
func fixedClock(start time.Time, step time.Duration) func() time.Time {
	t := start.Add(-step)
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

func TestRing_BeginRecordsCheckingStatus(t *testing.T) {
	r := New(10)
	r.Begin("req-1", "GET", "https://example.com:443/")

	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	if got, want := snap[0].Status, StatusChecking; got != want {
		t.Errorf("Status = %q, want %q", got, want)
	}
	if got, want := snap[0].URL, "https://example.com:443/"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

func TestRing_HoldPending_TransitionsThroughPending(t *testing.T) {
	r := New(10)
	r.Begin("req-1", "POST", "https://api.example.com:443/data")
	r.HoldPending("req-1", "hold-abc")

	snap := r.Snapshot()
	if got, want := snap[0].Status, StatusPending; got != want {
		t.Errorf("Status = %q, want %q", got, want)
	}
	if got, want := snap[0].HoldID, "hold-abc"; got != want {
		t.Errorf("HoldID = %q, want %q", got, want)
	}
}

func TestRing_Resolve_ClearsHoldID(t *testing.T) {
	r := New(10)
	r.Begin("req-1", "GET", "https://example.com:443/")
	r.HoldPending("req-1", "hold-abc")
	r.Resolve("req-1", "200")

	snap := r.Snapshot()
	if got, want := snap[0].Status, "200"; got != want {
		t.Errorf("Status = %q, want %q", got, want)
	}
	if snap[0].HoldID != "" {
		t.Errorf("HoldID = %q after resolve, want empty", snap[0].HoldID)
	}
}

func TestRing_HoldPending_UnknownIDIsNoOp(t *testing.T) {
	r := New(10)
	r.HoldPending("never-began", "hold-x")
	if got := r.Snapshot(); len(got) != 0 {
		t.Errorf("snapshot len = %d, want 0", len(got))
	}
}

func TestRing_Resolve_UnknownIDIsNoOp(t *testing.T) {
	r := New(10)
	r.Resolve("never-began", "200")
	if got := r.Snapshot(); len(got) != 0 {
		t.Errorf("snapshot len = %d, want 0", len(got))
	}
}

func TestRing_EvictsOldestAtCap(t *testing.T) {
	r := New(3)
	for _, id := range []string{"a", "b", "c"} {
		r.Begin(id, "GET", "https://example.com/"+id)
	}
	// "d" arrives — "a" must be evicted.
	r.Begin("d", "GET", "https://example.com/d")

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(snap))
	}
	for _, op := range snap {
		if op.RequestID == "a" {
			t.Errorf("oldest id 'a' was not evicted; snap = %+v", snap)
		}
	}
}

func TestRing_SnapshotIsCopy(t *testing.T) {
	r := New(10)
	r.Begin("req-1", "GET", "https://example.com/")
	snap := r.Snapshot()
	snap[0].Status = "tampered"

	again := r.Snapshot()
	if again[0].Status == "tampered" {
		t.Errorf("snapshot mutation leaked back into ring state")
	}
}

func TestRing_SnapshotOrderedNewestFirst(t *testing.T) {
	r := New(10)
	r.now = fixedClock(time.Unix(1_700_000_000, 0).UTC(), time.Second)
	r.Begin("req-old", "GET", "https://old.example/")
	r.Begin("req-mid", "GET", "https://mid.example/")
	r.Begin("req-new", "GET", "https://new.example/")

	snap := r.Snapshot()
	if got, want := []string{snap[0].RequestID, snap[1].RequestID, snap[2].RequestID},
		[]string{"req-new", "req-mid", "req-old"}; !equalStrings(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestRing_StatusUpdate_SamePositionAfterResolve(t *testing.T) {
	// Pins the in-place-update contract: an operation that transitions
	// checking → pending → resolved keeps its identity (the same
	// request_id remains in the snapshot at the same index relative
	// to other ops that have not changed since).
	r := New(10)
	r.now = fixedClock(time.Unix(1_700_000_000, 0).UTC(), time.Second)
	r.Begin("req-A", "GET", "https://a.example/")
	r.Begin("req-B", "GET", "https://b.example/")
	r.Begin("req-C", "GET", "https://c.example/")

	// Resolve req-B; it bumps to newest by UpdatedAt.
	r.Resolve("req-B", "200")
	snap := r.Snapshot()

	// Find req-B in the snapshot — its Status must be "200" and there
	// must be exactly one entry for it (no duplication).
	count := 0
	var status string
	for _, op := range snap {
		if op.RequestID == "req-B" {
			count++
			status = op.Status
		}
	}
	if count != 1 {
		t.Errorf("req-B appears %d times after Resolve; want 1 (in-place update)", count)
	}
	if status != "200" {
		t.Errorf("req-B status after Resolve = %q, want %q", status, "200")
	}
}

func TestRing_ConcurrentBeginsAreSafe(t *testing.T) {
	r := New(1024)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "req-" + itoa(i)
			r.Begin(id, "GET", "https://example.com/"+id)
			r.HoldPending(id, "hold-"+itoa(i))
			r.Resolve(id, "200")
		}(i)
	}
	wg.Wait()
	snap := r.Snapshot()
	if len(snap) != 50 {
		t.Errorf("snapshot len = %d, want 50", len(snap))
	}
}

func TestRing_NilSafe(t *testing.T) {
	var r *Ring
	r.Begin("x", "GET", "/")
	r.HoldPending("x", "h")
	r.Resolve("x", "200")
	if got := r.Snapshot(); got != nil {
		t.Errorf("nil ring snapshot = %v, want nil", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [10]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
