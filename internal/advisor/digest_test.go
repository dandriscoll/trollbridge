package advisor

import (
	"testing"
)

func TestDigestRing_AppendsAndCaps(t *testing.T) {
	r := NewDigestRing(3)
	for i, host := range []string{"a", "b", "c", "d"} {
		r.Add(Digest{Host: host, Outcome: DigestOutcomeClassified, Port: i})
	}
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3 (cap)", len(snap))
	}
	// Oldest evicted; b, c, d remain in order.
	want := []string{"b", "c", "d"}
	for i, w := range want {
		if snap[i].Host != w {
			t.Errorf("snap[%d].Host = %q, want %q", i, snap[i].Host, w)
		}
	}
}

func TestDigestRing_SnapshotIsCopy(t *testing.T) {
	r := NewDigestRing(8)
	r.Add(Digest{Host: "x"})
	snap := r.Snapshot()
	snap[0].Host = "tampered"

	again := r.Snapshot()
	if again[0].Host == "tampered" {
		t.Errorf("snapshot mutation leaked back into ring state")
	}
}

func TestDigestRing_NilSafe(t *testing.T) {
	var r *DigestRing
	r.Add(Digest{Host: "x"}) // must not panic
	if got := r.Snapshot(); got != nil {
		t.Errorf("nil ring snapshot = %v, want nil", got)
	}
}

func TestDigestRing_DefaultCap(t *testing.T) {
	r := NewDigestRing(0)
	if got := r.cap; got != DigestDefaultCap {
		t.Errorf("cap = %d, want %d", got, DigestDefaultCap)
	}
}
