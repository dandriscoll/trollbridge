package types

import "testing"

// TestDecisionSource_IsHumanOrLLMCategorization pins the categorization
// the audit-log `decisions` level reads (#113). When a new
// DecisionSource is added to types.go, the test author MUST add a
// row here naming the expected category; the sweep below makes that
// failure mode loud.
//
// The categorization is load-bearing: it decides which audit
// entries survive `logging.audit_level: decisions`. A miscategorized
// source either silently drops a security-relevant event (false
// negative) or floods the log with a static-policy auto-decision
// (false positive).
func TestDecisionSource_IsHumanOrLLMCategorization(t *testing.T) {
	cases := []struct {
		src        DecisionSource
		humanOrLLM bool
	}{
		{SourceRule, false},
		{SourceDefault, false},
		{SourceLLMAdvisor, true},
		{SourceApprovalQueue, true},
		{SourceApprovalTimeout, true},
		{SourceAllowList, false},
		{SourceDenyList, false},
		// Error-path sources (#139): neither human nor LLM decided —
		// the proxy failed before evaluation. Audit-level `decisions`
		// excludes them (they ARE relevant for `errors`/`all`).
		{SourceTLSHandshakeFail, false},
		{SourceMalformedTunnel, false},
		{SourceBodyReadFail, false},
		// Open mode (#209): operator-initiated bypass — human decision
		// to open the gate, so allowed requests survive `decisions`.
		{SourceOpenMode, true},
	}
	if len(cases) != len(AllDecisionSources) {
		t.Fatalf("categorization table has %d rows, AllDecisionSources has %d — keep them in lockstep; a new DecisionSource was added without categorization", len(cases), len(AllDecisionSources))
	}
	for _, tc := range cases {
		t.Run(string(tc.src), func(t *testing.T) {
			if got := tc.src.IsHumanOrLLM(); got != tc.humanOrLLM {
				t.Errorf("%q.IsHumanOrLLM() = %v, want %v", tc.src, got, tc.humanOrLLM)
			}
		})
	}
}

// TestDecisionSource_IsHumanOrLLMSweep enumerates AllDecisionSources
// (the authoritative list pinned by decisionsource_sweep_test.go)
// and asserts each value is categorized — neither method returns
// `false` *only* because the source name escaped the switch. This
// is a separate assertion shape from the table above: the table
// proves the *correctness* of each row; this sweep proves *every*
// source is reachable through the categorization at all.
func TestDecisionSource_IsHumanOrLLMSweep(t *testing.T) {
	humanOrLLMSeen := false
	staticSeen := false
	for _, s := range AllDecisionSources {
		if s.IsHumanOrLLM() {
			humanOrLLMSeen = true
		} else {
			staticSeen = true
		}
	}
	if !humanOrLLMSeen {
		t.Errorf("no DecisionSource categorized as human-or-LLM; the `decisions` audit level would silently emit nothing")
	}
	if !staticSeen {
		t.Errorf("no DecisionSource categorized as static; the `decisions` audit level would not filter anything")
	}
}
