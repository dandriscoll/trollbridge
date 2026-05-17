package reloadstatus

import (
	"errors"
	"testing"
	"time"
)

// TestTracker_PopulatesErrorAndClearsOnSuccess pins #129's
// state-machine contract on the in-memory tracker: a failed reload
// populates LastError; a subsequent successful reload clears it;
// LastAt advances on every attempt regardless of outcome.
func TestTracker_PopulatesErrorAndClearsOnSuccess(t *testing.T) {
	var tr Tracker

	if got := tr.Get(); got.LastError != "" || !got.LastAt.IsZero() || got.LastSource != "" {
		t.Fatalf("fresh tracker should be zero-value; got %+v", got)
	}

	tr.Record("rules", errors.New("bad yaml"))
	got := tr.Get()
	if got.LastError != "bad yaml" {
		t.Errorf("after failure: LastError = %q, want %q", got.LastError, "bad yaml")
	}
	if got.LastSource != "rules" {
		t.Errorf("after failure: LastSource = %q, want %q", got.LastSource, "rules")
	}
	if got.LastAt.IsZero() {
		t.Error("after failure: LastAt should be non-zero")
	}
	failAt := got.LastAt

	// Sleep enough to ensure LastAt advances measurably; use a
	// small sleep — the test doesn't need exact timing, just a
	// non-equal value.
	time.Sleep(2 * time.Millisecond)

	tr.Record("config", nil)
	got = tr.Get()
	if got.LastError != "" {
		t.Errorf("after success: LastError = %q, want empty", got.LastError)
	}
	if got.LastSource != "config" {
		t.Errorf("after success: LastSource = %q, want %q", got.LastSource, "config")
	}
	if !got.LastAt.After(failAt) {
		t.Errorf("after success: LastAt did not advance (was %v, now %v)", failAt, got.LastAt)
	}

	// Re-fail to confirm we can re-enter the failed state from
	// success — this is what the TUI badge must signal after an
	// operator fixes a file and then re-breaks it.
	tr.Record("lists", errors.New("invalid host pattern"))
	got = tr.Get()
	if got.LastError != "invalid host pattern" {
		t.Errorf("after re-fail: LastError = %q, want %q", got.LastError, "invalid host pattern")
	}
	if got.LastSource != "lists" {
		t.Errorf("after re-fail: LastSource = %q, want %q", got.LastSource, "lists")
	}
}

// TestTracker_GetIsCopyOut confirms the snapshot returned by Get is
// not aliased to the tracker's internal state — mutating the
// returned struct must not race with subsequent reads.
func TestTracker_GetIsCopyOut(t *testing.T) {
	var tr Tracker
	tr.Record("rules", errors.New("first"))
	snap := tr.Get()
	snap.LastError = "MUTATED"
	if tr.Get().LastError != "first" {
		t.Error("Get returned an aliased pointer; tracker state was mutated by caller")
	}
}
