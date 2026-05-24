package configwrite

import (
	"strings"
	"testing"
)

// TestGeneralize_RemovesSourcesAndAddsPattern pins #173: accepting a
// generalization removes the more-specific source entries and adds the
// wildcard pattern, in one write.
func TestGeneralize_RemovesSourcesAndAddsPattern(t *testing.T) {
	path := writeFixture(t)
	// Seed two specific allow entries that the pattern will replace.
	if _, err := AddAllow(path, "GET api.example.com/v1/users/123"); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAllow(path, "GET api.example.com/v1/users/456"); err != nil {
		t.Fatal(err)
	}

	changed, err := Generalize(path, "allow", "GET api.example.com/v1/users/*",
		[]string{"GET api.example.com/v1/users/123", "GET api.example.com/v1/users/456"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed = false, want true")
	}
	got := read(t, path)
	if !strings.Contains(got, "GET api.example.com/v1/users/*") {
		t.Errorf("generalized pattern not added:\n%s", got)
	}
	for _, src := range []string{"users/123", "users/456"} {
		if strings.Contains(got, src) {
			t.Errorf("specific source %q not removed:\n%s", src, got)
		}
	}
	// Unrelated entries are untouched.
	if !strings.Contains(got, "existing.example") {
		t.Errorf("Generalize disturbed an unrelated allow entry:\n%s", got)
	}
}

// TestGeneralize_SkipsAbsentSource verifies a source not present is
// simply skipped; the pattern is still added.
func TestGeneralize_SkipsAbsentSource(t *testing.T) {
	path := writeFixture(t)
	changed, err := Generalize(path, "deny", "*.evil.example", []string{"not-present.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed = false, want true (pattern still added)")
	}
	if !strings.Contains(read(t, path), "*.evil.example") {
		t.Errorf("pattern not added when source absent")
	}
}

// TestGeneralize_PrunesAllRedundantNotJustSources pins #177: accepting a
// generalization removes every existing entry the new pattern covers —
// not only the explicitly-selected sources — while leaving unrelated
// entries and broader entries alone.
func TestGeneralize_PrunesAllRedundantNotJustSources(t *testing.T) {
	path := writeFixture(t)
	for _, e := range []string{
		"GET api.example.com/v1/users/1",
		"GET api.example.com/v1/users/2",
		"GET api.example.com/v1/users/3", // redundant but NOT a selected source
		"GET api.example.com/v1/orders/9", // different path prefix — keep
	} {
		if _, err := AddAllow(path, e); err != nil {
			t.Fatal(err)
		}
	}

	// Only /1 and /2 are passed as sources; /3 must still be pruned.
	_, err := Generalize(path, "allow", "GET api.example.com/v1/users/*",
		[]string{"GET api.example.com/v1/users/1", "GET api.example.com/v1/users/2"})
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	if !strings.Contains(got, "GET api.example.com/v1/users/*") {
		t.Errorf("pattern not added:\n%s", got)
	}
	for _, gone := range []string{"users/1", "users/2", "users/3"} {
		if strings.Contains(got, gone) {
			t.Errorf("redundant entry %q not pruned:\n%s", gone, got)
		}
	}
	// Unrelated and pre-existing entries survive.
	for _, kept := range []string{"orders/9", "existing.example"} {
		if !strings.Contains(got, kept) {
			t.Errorf("non-redundant entry %q was wrongly pruned:\n%s", kept, got)
		}
	}
}

// TestGeneralize_RejectsUnknownList guards the list argument.
func TestGeneralize_RejectsUnknownList(t *testing.T) {
	path := writeFixture(t)
	if _, err := Generalize(path, "bogus", "x", nil); err == nil {
		t.Error("expected error for unknown list")
	}
}
