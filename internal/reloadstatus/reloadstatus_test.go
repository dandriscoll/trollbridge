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

// TestTracker_MultiSourceFailingSources closes #165: when two
// sources fail simultaneously (config first, then rules), neither
// failure overwrites the other — both surface in FailingSources()
// and in Get().FailingSources. When a later success clears one
// source, the surviving failure stays in the list.
func TestTracker_MultiSourceFailingSources(t *testing.T) {
	var tr Tracker

	tr.Record("config", errors.New("bad yaml"))
	tr.Record("rules", errors.New("invalid host pattern"))

	got := tr.FailingSources()
	if len(got) != 2 || got[0] != "config" || got[1] != "rules" {
		t.Fatalf("FailingSources after config+rules fail: got %v, want [config rules]", got)
	}

	snap := tr.Get()
	if len(snap.FailingSources) != 2 || snap.FailingSources[0] != "config" || snap.FailingSources[1] != "rules" {
		t.Errorf("Get().FailingSources: got %v, want [config rules]", snap.FailingSources)
	}
	// Legacy single-source fields reflect the most-recent record.
	if snap.LastSource != "rules" {
		t.Errorf("LastSource = %q, want rules", snap.LastSource)
	}

	// Fix `config`; rules stays failing.
	tr.Record("config", nil)
	got = tr.FailingSources()
	if len(got) != 1 || got[0] != "rules" {
		t.Errorf("after config success: FailingSources = %v, want [rules]", got)
	}

	// Fix rules too; everything clean.
	tr.Record("rules", nil)
	got = tr.FailingSources()
	if got != nil {
		t.Errorf("after all-clean: FailingSources = %v, want nil", got)
	}
	if snap := tr.Get(); snap.FailingSources != nil {
		t.Errorf("Get().FailingSources after all-clean = %v, want nil", snap.FailingSources)
	}
}

// TestTracker_SourcesSnapshot confirms the per-source map is a
// caller-owned copy that surfaces every source the tracker has
// recorded, regardless of whether they're currently failing.
func TestTracker_SourcesSnapshot(t *testing.T) {
	var tr Tracker
	tr.Record("config", nil)
	tr.Record("rules", errors.New("oops"))
	src := tr.Sources()
	if len(src) != 2 {
		t.Fatalf("Sources len = %d, want 2", len(src))
	}
	if src["config"].LastError != "" {
		t.Errorf("config entry should be clean")
	}
	if src["rules"].LastError != "oops" {
		t.Errorf("rules entry should carry the error")
	}
	// Mutating the copy must not affect the tracker.
	src["rules"] = Status{LastError: "MUTATED"}
	if tr.Sources()["rules"].LastError != "oops" {
		t.Error("Sources() returned an aliased map")
	}
}
