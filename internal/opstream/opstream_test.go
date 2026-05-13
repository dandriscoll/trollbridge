package opstream

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func jsonMarshalImpl(v any) ([]byte, error) { return json.Marshal(v) }
func bytesContains(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}

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
	r.Resolve("req-1", "200", 0, 0)

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
	r.Resolve("never-began", "200", 0, 0)
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
	r.Resolve("req-B", "200", 0, 0)
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
			r.Resolve(id, "200", 0, 0)
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
	r.Resolve("x", "200", 0, 0)
	if got := r.Snapshot(); got != nil {
		t.Errorf("nil ring snapshot = %v, want nil", got)
	}
	if r.Rebind("x", "y", "GET", "/") {
		t.Errorf("nil ring Rebind returned true; want false")
	}
}

func TestRing_Rebind_RelabelsExistingEntry(t *testing.T) {
	r := New(10)
	r.Begin("connect-1", "CONNECT", "api.example.com")
	r.Resolve("connect-1", "200", 0, 0)

	ok := r.Rebind("connect-1", "inner-1", "GET", "https://api.example.com/path")
	if !ok {
		t.Fatalf("Rebind returned false on existing id")
	}

	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	got := snap[0]
	if got.RequestID != "inner-1" {
		t.Errorf("RequestID = %q, want inner-1", got.RequestID)
	}
	if got.Method != "GET" {
		t.Errorf("Method = %q, want GET", got.Method)
	}
	if got.URL != "https://api.example.com/path" {
		t.Errorf("URL = %q, want https://api.example.com/path", got.URL)
	}
	if got.Status != StatusChecking {
		t.Errorf("Status = %q, want %q (rebind resets to checking)", got.Status, StatusChecking)
	}
}

func TestRing_Rebind_UnknownIDReturnsFalse(t *testing.T) {
	r := New(10)
	if r.Rebind("never-began", "new", "GET", "/") {
		t.Errorf("Rebind on unknown id returned true; want false")
	}
}

func TestRing_Rebind_SameIDIsRelabelOnly(t *testing.T) {
	r := New(10)
	r.Begin("req-1", "CONNECT", "host")
	if !r.Rebind("req-1", "req-1", "GET", "https://host/p") {
		t.Fatalf("Rebind(same id) returned false")
	}
	snap := r.Snapshot()
	if snap[0].Method != "GET" || snap[0].URL != "https://host/p" {
		t.Errorf("relabel did not apply: %+v", snap[0])
	}
}

func TestRing_Rebind_ClashReturnsFalse(t *testing.T) {
	r := New(10)
	r.Begin("a", "CONNECT", "h")
	r.Begin("b", "GET", "https://h/x")
	if r.Rebind("a", "b", "GET", "https://h/y") {
		t.Errorf("Rebind into existing newID returned true; want false")
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

// TestOp_JSONShape_OmitemptyHoldsForZeroValues closes the omitempty
// regression-test bullet of #104. Marshaling an Op with the three
// omitempty-tagged fields at zero must produce JSON that omits
// those keys entirely; with non-zero values, the keys must appear.
func TestOp_JSONShape_OmitemptyHoldsForZeroValues(t *testing.T) {
	zero := Op{
		RequestID: "r1",
		Method:    "GET",
		URL:       "https://example.com/",
		// LatencyMS, ResponseSizeBytes, HoldID intentionally zero.
	}
	b, err := jsonMarshal(zero)
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	for _, banned := range []string{"latency_ms", "response_size_bytes", "hold_id"} {
		if containsKey(b, banned) {
			t.Errorf("zero-Op JSON leaks %q key:\n%s", banned, b)
		}
	}

	withVals := Op{
		RequestID:         "r2",
		Method:            "POST",
		URL:               "https://example.com/",
		HoldID:            "hold-42",
		LatencyMS:         123,
		ResponseSizeBytes: 4096,
	}
	b2, err := jsonMarshal(withVals)
	if err != nil {
		t.Fatalf("marshal withVals: %v", err)
	}
	for _, expected := range []string{"latency_ms", "response_size_bytes", "hold_id"} {
		if !containsKey(b2, expected) {
			t.Errorf("non-zero-Op JSON missing %q key:\n%s", expected, b2)
		}
	}
}

// jsonMarshal is a tiny wrapper around encoding/json.Marshal so
// containsKey can be a pure substring check; tests don't have to
// re-do the encoding step inline.
func jsonMarshal(v any) ([]byte, error) { return jsonMarshalImpl(v) }

func containsKey(b []byte, key string) bool {
	return bytesContains(b, []byte("\""+key+"\""))
}
