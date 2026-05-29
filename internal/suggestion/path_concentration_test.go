package suggestion

import (
	"context"
	"testing"
)

// TestProduce_EvenBreadth_KeepsHostWide pins the negative direction
// of #190's concentration logic: when the operator's allow-list
// entries are evenly distributed across path prefixes, the scorer
// should keep offering the broader `host/*` suggestion.
//
// Three entries under three distinct prefixes — none has ≥80%
// share. The current coverage-first ranking (#186) picks `host/*`
// and the new concentration check finds no qualifying narrower
// candidate.
//
// This is the same fixture shape as TestProduceOffersBroadestCoverageFirst
// reformulated to be explicit about the breadth interpretation.
func TestProduce_EvenBreadth_KeepsHostWide(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/v1/users/1",
		"GET https://api.example.com/v2/orders/1",
		"GET https://api.example.com/webhook/1",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())

	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	if got := active.Candidate.SuggestedPattern; got != "GET https://api.example.com/*" {
		t.Errorf("even-breadth: offered pattern = %q; want %q",
			got, "GET https://api.example.com/*")
	}
}

// TestProduce_ConcentratedTraffic_PrefersNarrower is the load-
// bearing #190 test: when ≥80% of the host's entries cluster
// under a single 1-segment prefix, the scorer prefers the
// narrower `host/<prefix>/*` over the broader `host/*`.
//
// Fixture: four `/api/*` entries + one `/webhook/...` outlier.
// 4/5 = 80%, exactly at threshold. The scorer must swap from
// host-wide to `host/api/*`.
func TestProduce_ConcentratedTraffic_PrefersNarrower(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/api/users/1",
		"GET https://api.example.com/api/users/2",
		"GET https://api.example.com/api/orders/1",
		"GET https://api.example.com/api/orders/2",
		"GET https://api.example.com/webhook/event/1",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())

	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	got := active.Candidate.SuggestedPattern
	wantNarrower := "GET https://api.example.com/api/*"
	wantBroader := "GET https://api.example.com/*"
	if got == wantBroader {
		t.Errorf("concentrated-traffic: offered the broader %q; want the narrower %q "+
			"(4 of 5 entries cluster in /api/* — 80%% concentration triggers narrower-allow per #190)",
			wantBroader, wantNarrower)
	}
	if got != wantNarrower {
		t.Errorf("concentrated-traffic: offered pattern = %q; want %q", got, wantNarrower)
	}
}

// TestProduce_BelowConcentrationThreshold_KeepsHostWide pins the
// boundary: when concentration is below 80%, the scorer keeps
// the broader allow.
//
// Fixture: three `/api/*` entries + two outliers = 3/5 = 60%
// concentration, below threshold. Broader stays.
func TestProduce_BelowConcentrationThreshold_KeepsHostWide(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://api.example.com/api/users/1",
		"GET https://api.example.com/api/users/2",
		"GET https://api.example.com/api/orders/1",
		"GET https://api.example.com/webhook/event/1",
		"GET https://api.example.com/probe/health/1",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.Tick(context.Background())

	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	if got := active.Candidate.SuggestedPattern; got != "GET https://api.example.com/*" {
		t.Errorf("below-threshold (60%% concentration): offered %q; want host-wide %q",
			got, "GET https://api.example.com/*")
	}
}
