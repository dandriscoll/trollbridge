package suggestion

import (
	"context"
	"testing"
)

// TestProduceOffersBroadestCoverageFirst pins #186: when a host yields
// both a narrow per-prefix subset candidate (2 entries) and a host-wide
// candidate (all 3 entries), the suggester offers the host-wide one
// first — "generalize against all of them before a subset". Both groups
// carry a single url_segment axis, so the old most-axes ranking would
// fall to the lexicographic-key tiebreak; the stray entry `/v1/zzz/9`
// is chosen so the subset's key sorts BEFORE the host-wide key (the
// subset key is a prefix of it), meaning the old tiebreak would pick
// the subset. Only coverage-first selection offers the host-wide
// pattern — so this fails on the pre-#186 ranking.
func TestProduceOffersBroadestCoverageFirst(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/1",
		"GET https://api.example.com/v1/users/2",
		"GET https://api.example.com/v1/zzz/9",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})

	m.Tick(context.Background())

	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	if got := active.Candidate.SuggestedPattern; got != "GET https://api.example.com/*" {
		t.Errorf("offered pattern = %q; want the host-wide %q", got, "GET https://api.example.com/*")
	}
	if got := len(active.Candidate.SourceEntries); got != 3 {
		t.Errorf("offered source count = %d; want 3 (covers the whole host)", got)
	}
}
