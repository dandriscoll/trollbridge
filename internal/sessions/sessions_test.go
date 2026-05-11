package sessions

import (
	"strings"
	"sync"
	"testing"
)

func TestGetOrCreate_ReturnsExistingSessionAcrossCalls(t *testing.T) {
	tr := New()
	s1 := tr.GetOrCreate("1.2.3.4:1000", "alice")
	if s1.ID == "" || !strings.HasPrefix(s1.ID, "sess-") {
		t.Errorf("session ID not assigned with sess- prefix: %q", s1.ID)
	}
	s2 := tr.GetOrCreate("1.2.3.4:1000", "alice")
	if s1 != s2 {
		t.Errorf("second GetOrCreate returned a different *Session; want pointer equality")
	}
	if s2.DecisionCount != 1 {
		t.Errorf("DecisionCount on second call: got %d, want 1", s2.DecisionCount)
	}
}

func TestGetOrCreate_AnonymousDoesNotOverwriteIdentity(t *testing.T) {
	tr := New()
	s := tr.GetOrCreate("1.2.3.4:1000", "alice")
	tr.GetOrCreate("1.2.3.4:1000", "anonymous")
	tr.GetOrCreate("1.2.3.4:1000", "")
	if s.IdentityID != "alice" {
		t.Errorf("identity: got %q, want %q (anonymous/empty must not overwrite)", s.IdentityID, "alice")
	}
}

func TestGetOrCreate_DistinctAddrsGetDistinctSessions(t *testing.T) {
	tr := New()
	a := tr.GetOrCreate("1.2.3.4:1000", "alice")
	b := tr.GetOrCreate("1.2.3.4:1001", "bob")
	if a.ID == b.ID {
		t.Error("distinct client addrs must get distinct session IDs")
	}
	if got := len(tr.Snapshot()); got != 2 {
		t.Errorf("snapshot length: got %d, want 2", got)
	}
}

func TestDrop_RemovesSession(t *testing.T) {
	tr := New()
	tr.GetOrCreate("1.2.3.4:1000", "alice")
	tr.GetOrCreate("1.2.3.4:1001", "bob")
	tr.Drop("1.2.3.4:1000")
	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("after drop: snapshot len = %d, want 1", len(snap))
	}
	if snap[0].ClientAddr != "1.2.3.4:1001" {
		t.Errorf("wrong session survived drop: %q", snap[0].ClientAddr)
	}
}

func TestSnapshot_ReturnsCopy(t *testing.T) {
	tr := New()
	tr.GetOrCreate("1.2.3.4:1000", "alice")
	snap := tr.Snapshot()
	snap[0].IdentityID = "mutated"
	again := tr.Snapshot()
	if again[0].IdentityID == "mutated" {
		t.Error("Snapshot returned by-reference; caller mutation leaked into Tracker state")
	}
}

func TestTracker_ConcurrentSafe(t *testing.T) {
	tr := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := "10.0.0.1:" + string(rune('A'+(i%26)))
			tr.GetOrCreate(addr, "x")
			tr.Snapshot()
		}(i)
	}
	wg.Wait()
	// Sanity: no panic, no race detector trip if -race is set.
	if got := len(tr.Snapshot()); got == 0 || got > 26 {
		t.Errorf("post-concurrent snapshot size %d outside expected [1, 26]", got)
	}
}