package opstream

import "testing"

// TestRing_ResolveCapturesLatencyAndSize pins the new fields land
// on the Op after Resolve (#90).
func TestRing_ResolveCapturesLatencyAndSize(t *testing.T) {
	r := New(8)
	r.Begin("req-1", "GET", "https://x/")
	r.Resolve("req-1", "200", 142, 2318)

	out := r.Snapshot()
	if len(out) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(out))
	}
	if out[0].LatencyMS != 142 {
		t.Errorf("LatencyMS = %d, want 142", out[0].LatencyMS)
	}
	if out[0].ResponseSizeBytes != 2318 {
		t.Errorf("ResponseSizeBytes = %d, want 2318", out[0].ResponseSizeBytes)
	}
}

// TestRing_ResolveZeroLeavesFieldsUntouched pins that a Resolve
// with 0 latency / 0 size does not clobber a previous non-zero
// value — useful for the transient "running" transition that fires
// before terminal data is known.
func TestRing_ResolveZeroLeavesFieldsUntouched(t *testing.T) {
	r := New(8)
	r.Begin("req-1", "GET", "https://x/")
	r.Resolve("req-1", "200", 50, 100)
	// Subsequent "transient" resolve with zeros should not overwrite.
	r.Resolve("req-1", "running", 0, 0)
	out := r.Snapshot()
	if out[0].LatencyMS != 50 || out[0].ResponseSizeBytes != 100 {
		t.Errorf("zero-arg Resolve clobbered previous metadata: %+v", out[0])
	}
}
