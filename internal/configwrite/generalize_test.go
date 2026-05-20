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

// TestGeneralize_RejectsUnknownList guards the list argument.
func TestGeneralize_RejectsUnknownList(t *testing.T) {
	path := writeFixture(t)
	if _, err := Generalize(path, "bogus", "x", nil); err == nil {
		t.Error("expected error for unknown list")
	}
}
