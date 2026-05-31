package suggestion

import (
	"context"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/generalize"
)

// stubRecognizer maps hosts to (pattern, components).
type stubRecognizer struct{}

func (stubRecognizer) Recognize(host string, port int, scheme, path string) (string, map[string]string, bool) {
	if host != "management.azure.com" {
		return "", nil, false
	}
	// Minimal extraction: subscription from /subscriptions/{x}.
	sub := ""
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 0; i+1 < len(segs); i++ {
		if strings.ToLower(segs[i]) == "subscriptions" {
			sub = segs[i+1]
		}
	}
	return "azure_arm", map[string]string{
		"subscription":   sub,
		"resource_group": "",
		"provider":       "",
		"resource_type":  "",
		"resource_name":  "",
	}, true
}

func TestManager_PatternRecognizer_EmitsPatternCandidate(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, &fakeWriter{})
	m.SetPatternRecognizer(stubRecognizer{})
	m.SetRulesPath("/tmp/test-rules.yaml")
	m.SuggestNow(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	// Look across the active + AllAxes for a pattern candidate.
	got := active.Candidate
	if got.PatternMatch == nil {
		// The flat detectors may rank first; check AllAxes too.
		found := false
		for _, c := range active.AllAxes {
			if c.PatternMatch != nil {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected a pattern-shaped candidate in the offered set; got axes %v", axisNamesOf(active.AllAxes))
		}
	}
}

func axisNamesOf(cs []generalize.Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c.Axis)
	}
	return out
}

func TestManager_AcceptPattern_CallsWriterAcceptPath(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}}
	writer := &fakeWriter{}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, writer)
	m.SetPatternRecognizer(stubRecognizer{})
	m.SetRulesPath("/tmp/test-rules.yaml")
	m.SuggestNow(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("expected an active suggestion")
	}
	// Force the active to the pattern candidate if it's not the
	// initial pick (advisor priority may favor pattern, but we
	// don't depend on that here).
	if active.Candidate.PatternMatch == nil {
		for _, c := range active.AllAxes {
			if c.PatternMatch != nil {
				m.mu.Lock()
				m.active.Candidate = c
				m.active.OfferedAxes = []string{string(c.Axis)}
				m.mu.Unlock()
				active = m.Active()
				break
			}
		}
	}
	if active.Candidate.PatternMatch == nil {
		t.Fatal("no pattern candidate available to accept")
	}
	if err := m.Accept(context.Background(), active.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(writer.patternAccepts) != 1 {
		t.Fatalf("expected one AcceptPatternSuggestion call; got %d", len(writer.patternAccepts))
	}
	rec := writer.patternAccepts[0]
	if rec.rulesPath != "/tmp/test-rules.yaml" {
		t.Fatalf("rulesPath: %q", rec.rulesPath)
	}
	if rec.pattern != "azure_arm" {
		t.Fatalf("pattern: %q", rec.pattern)
	}
	if rec.effect != "allow" {
		t.Fatalf("effect: %q", rec.effect)
	}
	if !strings.HasPrefix(rec.ruleID, "suggested-azure_arm-") {
		t.Fatalf("ruleID format: %q", rec.ruleID)
	}
}

func TestManager_AcceptPattern_EmptyRulesPath_Errors(t *testing.T) {
	cfg := enabledConfig()
	lists := &stubLists{allow: []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}}
	writer := &fakeWriter{}
	m, _ := newTestManager(t, cfg, &stubQueue{}, lists, writer)
	m.SetPatternRecognizer(stubRecognizer{})
	// No rulesPath set on purpose.
	m.SuggestNow(context.Background())
	active := m.Active()
	if active == nil {
		t.Fatal("no active suggestion")
	}
	if active.Candidate.PatternMatch == nil {
		for _, c := range active.AllAxes {
			if c.PatternMatch != nil {
				m.mu.Lock()
				m.active.Candidate = c
				m.mu.Unlock()
				active = m.Active()
				break
			}
		}
	}
	if active.Candidate.PatternMatch == nil {
		t.Skip("no pattern candidate to accept (advisor produced none)")
	}
	err := m.Accept(context.Background(), active.ID)
	if err == nil || !strings.Contains(err.Error(), "policy.include") {
		t.Fatalf("expected actionable error about policy.include; got %v", err)
	}
}
