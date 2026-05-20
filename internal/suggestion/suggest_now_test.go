package suggestion

import (
	"context"
	"testing"
)

// TestSuggestNow_BypassesQuietGate pins #174: SuggestNow produces a
// suggestion even when the quiet predicate would block Tick (here, a
// non-empty queue). Tick must stay silent; SuggestNow must offer.
func TestSuggestNow_BypassesQuietGate(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users",
		"POST https://api.example.com/v1/users",
	}}
	queue := &stubQueue{pending: []QueueSnapshot{{ID: "h1"}}} // not quiet
	m, _ := newTestManager(t, cfg, queue, lists, &fakeWriter{})

	m.Tick(context.Background())
	if m.Active() != nil {
		t.Fatalf("Tick produced a suggestion despite a non-empty queue")
	}

	m.SuggestNow(context.Background())
	got := m.Active()
	if got == nil {
		t.Fatalf("SuggestNow did not produce a suggestion on demand")
	}
	if got.Candidate.SuggestedPattern != "* https://api.example.com/v1/users" {
		t.Errorf("wrong pattern: %q", got.Candidate.SuggestedPattern)
	}
}

// TestSuggestNow_NoOpportunityLeavesNil verifies an on-demand scan with
// nothing to offer leaves no active suggestion (the TUI surfaces the
// "none found" message from the nil result).
func TestSuggestNow_NoOpportunityLeavesNil(t *testing.T) {
	cfg := enabledConfig()
	m, _ := newTestManager(t, cfg, &stubQueue{}, &stubLists{}, &fakeWriter{})
	m.SuggestNow(context.Background())
	if m.Active() != nil {
		t.Errorf("expected no active suggestion when lists are empty")
	}
}
