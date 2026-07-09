package suggestion

import (
	"context"
	"testing"
)

// twoGroupLists returns an allow list that yields two independent
// generalization groups (two distinct hosts, each a 2-entry
// url_segment set) with EQUAL coverage and axis count — so the group
// chosen first is decided only by the #214 shuffle tie-break.
func twoGroupLists() *stubLists {
	return &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/123",
		"GET https://api.example.com/v1/users/456",
		"GET https://cdn.other.com/assets/111",
		"GET https://cdn.other.com/assets/222",
	}}
}

// TestSkipDefersWithoutDecisionAndOffersNext pins #214: skip clears the
// active recommendation WITHOUT writing a decline row or reloading, and
// the next detection offers a DIFFERENT recommendation (the skipped one
// is suppressed for the process — the #188 "stuck re-recommending"
// shape must not occur).
func TestSkipDefersWithoutDecisionAndOffersNext(t *testing.T) {
	cfg := enabledConfig()
	writer := &fakeWriter{}
	m, reloaded := newTestManager(t, cfg, &stubQueue{}, twoGroupLists(), writer)
	m.shuffleSeed = 1 // deterministic tie-break for the test

	m.Tick(context.Background())
	first := m.Active()
	if first == nil {
		t.Fatal("expected a first suggestion")
	}
	firstKey := first.Candidate.CanonicalKey()

	if err := m.Skip(context.Background(), first.ID); err != nil {
		t.Fatalf("Skip: %v", err)
	}
	// Skip persists nothing and reloads nothing.
	if len(writer.declined) != 0 {
		t.Errorf("skip wrote a decline row; got %v", writer.declined)
	}
	if len(writer.addedAllow) != 0 || len(writer.removed) != 0 {
		t.Errorf("skip mutated lists; addedAllow=%v removed=%v", writer.addedAllow, writer.removed)
	}
	if *reloaded {
		t.Errorf("skip triggered a config reload; it should not")
	}
	if m.Active() != nil {
		t.Errorf("skip did not clear the active suggestion")
	}

	// Next detection offers the OTHER group, not the skipped one.
	m.Tick(context.Background())
	second := m.Active()
	if second == nil {
		t.Fatal("expected a second suggestion after skipping the first")
	}
	if second.Candidate.CanonicalKey() == firstKey {
		t.Errorf("skip re-offered the same recommendation %q (the #188 stuck shape)", firstKey)
	}

	// Skipping the second too leaves nothing to offer this session.
	if err := m.Skip(context.Background(), second.ID); err != nil {
		t.Fatalf("Skip second: %v", err)
	}
	m.Tick(context.Background())
	if m.Active() != nil {
		t.Errorf("both groups skipped, yet a suggestion was offered: %+v", m.Active())
	}
}

// TestSkipIDMismatchAndNoActive pins the error contract: skip returns
// ErrIDMismatch for a stale id and ErrNoActive when nothing is offered,
// matching Accept/Decline.
func TestSkipIDMismatchAndNoActive(t *testing.T) {
	cfg := enabledConfig()
	m, _ := newTestManager(t, cfg, &stubQueue{}, twoGroupLists(), &fakeWriter{})

	if err := m.Skip(context.Background(), "nope"); err != ErrNoActive {
		t.Errorf("skip with no active = %v, want ErrNoActive", err)
	}
	m.Tick(context.Background())
	if m.Active() == nil {
		t.Fatal("expected active")
	}
	if err := m.Skip(context.Background(), "stale-id"); err != ErrIDMismatch {
		t.Errorf("skip with stale id = %v, want ErrIDMismatch", err)
	}
	if m.Active() == nil {
		t.Errorf("a mismatched skip cleared the active suggestion")
	}
}

// TestShuffleVariesTieButPreservesCoveragePolicy pins #214's shuffle:
// (a) for equal-priority groups the chosen-first group varies with the
// seed (so the operator does not always see the same one first), while
// (b) the same seed is stable, and (c) a strictly-higher-coverage group
// still always wins regardless of seed (#186 is unaffected).
func TestShuffleVariesTieButPreservesCoveragePolicy(t *testing.T) {
	cfg := enabledConfig()

	// (a)+(b): equal-coverage two-group fixture. Sweep seeds; both
	// groups must be chosen for some seed, and each seed must be stable.
	chosen := map[string]int{}
	for seed := uint64(0); seed < 32; seed++ {
		m, _ := newTestManager(t, cfg, &stubQueue{}, twoGroupLists(), &fakeWriter{})
		m.shuffleSeed = seed
		m.Tick(context.Background())
		a := m.Active()
		if a == nil {
			t.Fatalf("seed %d: expected a suggestion", seed)
		}
		key := a.Candidate.CanonicalKey()
		chosen[key]++

		// Stability: a fresh manager with the same seed picks the same group.
		m2, _ := newTestManager(t, cfg, &stubQueue{}, twoGroupLists(), &fakeWriter{})
		m2.shuffleSeed = seed
		m2.Tick(context.Background())
		if b := m2.Active(); b == nil || b.Candidate.CanonicalKey() != key {
			t.Errorf("seed %d not stable: %v vs %q", seed, b, key)
		}
	}
	if len(chosen) < 2 {
		t.Errorf("shuffle never varied the tie-break across 32 seeds: %v", chosen)
	}

	// (c): give one host strictly more coverage (3 entries vs 2). It
	// must win for EVERY seed — shuffle only breaks exact ties.
	highCoverage := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/1",
		"GET https://api.example.com/v1/users/2",
		"GET https://api.example.com/v1/users/3",
		"GET https://cdn.other.com/assets/111",
		"GET https://cdn.other.com/assets/222",
	}}
	for seed := uint64(0); seed < 32; seed++ {
		m, _ := newTestManager(t, cfg, &stubQueue{}, highCoverage, &fakeWriter{})
		m.shuffleSeed = seed
		m.Tick(context.Background())
		a := m.Active()
		if a == nil {
			t.Fatalf("seed %d: expected a suggestion", seed)
		}
		if got := a.Candidate.List; got != "allow" {
			t.Fatalf("unexpected list %q", got)
		}
		// The 3-entry api.example.com set must be the one offered.
		if len(a.Candidate.SourceEntries) != 3 {
			t.Errorf("seed %d: coverage-first violated — offered a %d-entry set, want the 3-entry set",
				seed, len(a.Candidate.SourceEntries))
		}
	}
}
