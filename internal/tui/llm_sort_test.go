package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
)

// TestDisplayedDigests_DefaultTimeOrder pins the default LLM panel
// sort: newest first (#198 default; matches the historical
// behavior).
func TestDisplayedDigests_DefaultTimeOrder(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Digests: []advisor.Digest{
			{RequestID: "old", Host: "c.example", Timestamp: t0.Add(1 * time.Second)},
			{RequestID: "mid", Host: "a.example", Timestamp: t0.Add(2 * time.Second)},
			{RequestID: "new", Host: "b.example", Timestamp: t0.Add(3 * time.Second)},
		},
	}
	got := displayedDigests(m)
	want := []string{"new", "mid", "old"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].RequestID != want[i] {
			t.Errorf("displayed[%d] = %q, want %q", i, got[i].RequestID, want[i])
		}
	}
}

// TestDisplayedDigests_URLSortAlphabetical pins #198: with
// LLMSortByURL=true, digests render alphabetically by URL.
func TestDisplayedDigests_URLSortAlphabetical(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		LLMSortByURL: true,
		Digests: []advisor.Digest{
			{RequestID: "c", Method: "GET", Scheme: "https", Host: "c.example", Port: 443, Path: "/", Timestamp: t0.Add(1 * time.Second)},
			{RequestID: "a", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", Timestamp: t0.Add(2 * time.Second)},
			{RequestID: "b", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", Timestamp: t0.Add(3 * time.Second)},
		},
	}
	got := displayedDigests(m)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].RequestID != want[i] {
			t.Errorf("displayed[%d] (URL-sort) = %q, want %q", i, got[i].RequestID, want[i])
		}
	}
}

// TestApplyKeyLLM_SToggleFlipsLLMSortByURL pins the keystroke:
// pressing `s` in the LLM panel toggles the sort mode.
func TestApplyKeyLLM_SToggleFlipsLLMSortByURL(t *testing.T) {
	m := Model{
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelLLM,
		Focused:         PaneConsole,
	}
	if m.LLMSortByURL {
		t.Fatal("setup: LLMSortByURL should default to false")
	}
	m, _ = Apply(m, KeyEvent{Rune: 's'})
	if !m.LLMSortByURL {
		t.Errorf("after first 's': LLMSortByURL = false, want true")
	}
	m, _ = Apply(m, KeyEvent{Rune: 's'})
	if m.LLMSortByURL {
		t.Errorf("after second 's': LLMSortByURL = true, want false (toggle)")
	}
}

// TestDigestSelectedIndex_RespectsURLSort pins that the cursor's
// display index is computed against the URL-sorted order when
// LLMSortByURL is true. This is what makes Up/Down navigation
// follow the visible order rather than the chronological order.
func TestDigestSelectedIndex_RespectsURLSort(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		LLMSortByURL:   true,
		DigestSelected: "c",
		Digests: []advisor.Digest{
			{RequestID: "c", Method: "GET", Scheme: "https", Host: "c.example", Port: 443, Path: "/", Timestamp: t0.Add(1 * time.Second)},
			{RequestID: "a", Method: "GET", Scheme: "https", Host: "a.example", Port: 443, Path: "/", Timestamp: t0.Add(2 * time.Second)},
			{RequestID: "b", Method: "GET", Scheme: "https", Host: "b.example", Port: 443, Path: "/", Timestamp: t0.Add(3 * time.Second)},
		},
	}
	// In URL sort: a (idx 0), b (idx 1), c (idx 2). Cursor on "c" → display index 2.
	if got := digestSelectedIndex(m); got != 2 {
		t.Errorf("digestSelectedIndex (URL-sort, cursor on c) = %d, want 2", got)
	}
}
