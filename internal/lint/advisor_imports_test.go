package lint

import (
	"sort"
	"strings"
	"testing"
)

// TestAlignmentPrinciple1_AdvisorDoesNotImportConfigwrite is the
// structural enforcer for the first half of docs/alignment-principles.md
// §1: the LLM advisor must not be able to mutate the operator's
// allow/deny lists. The behavior test
// internal/approvals/queue_llm_no_persist_test.go
// (TestResolveByAdvisor_DoesNotFirePersistCb_*) catches the
// runtime case; this test catches the import-graph drift case at
// build time. Prevention class: #193 / #200.
//
// A failure here means a recent commit has wired internal/advisor
// to internal/configwrite — either directly or via an intermediate
// package (e.g., a "suggestion adapter" that imports both). The
// fix is structural: route any list-mutation through an
// interface/seam that lives in the operator-action layer
// (cmd/trollbridge/run.go, internal/console, internal/suggestion's
// ConfigWriter seam) and never lets the advisor reach configwrite
// in the import graph.
func TestAlignmentPrinciple1_AdvisorDoesNotImportConfigwrite(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	mod, err := modulePath(root)
	if err != nil {
		t.Fatalf("modulePath: %v", err)
	}
	imports, err := packageImports(root, mod)
	if err != nil {
		t.Fatalf("packageImports: %v", err)
	}
	from := mod + "/internal/advisor"
	target := mod + "/internal/configwrite"
	if _, ok := imports[from]; !ok {
		t.Fatalf("expected to find package %s in import map; got keys: %v", from, keysSorted(imports))
	}
	if chain := reaches(imports, from, target); chain != nil {
		t.Errorf("alignment §1 violation: %s reaches %s via import chain %s; "+
			"see docs/alignment-principles.md §1 (the LLM advisor must "+
			"not be able to mutate the allow/deny lists). Route any "+
			"new mutation through the operator-action layer "+
			"(internal/console, cmd/trollbridge/run.go, "+
			"internal/suggestion's ConfigWriter seam) and remove the "+
			"transitive import path.",
			from, target, strings.Join(chain, " → "))
	}
}

// TestAlignmentPrinciple3_AdvisorDoesNotImportHostlist is the
// structural enforcer for docs/alignment-principles.md §3: the LLM
// advisor must not interpret allow/deny patterns — that's the
// engine's job. Importing internal/hostlist would let the advisor
// call hostlist.Match (or reimplement matching against the same
// types), creating the two-matchers-diverge failure mode the
// principle exists to prevent.
//
// A failure here means a recent commit has given the advisor
// access to hostlist symbols. The fix is to consume any
// match-result the advisor needs as data on the Input struct
// (already populated by the engine before consultAdvisorForHold
// fires), not by importing the matcher.
func TestAlignmentPrinciple3_AdvisorDoesNotImportHostlist(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	mod, err := modulePath(root)
	if err != nil {
		t.Fatalf("modulePath: %v", err)
	}
	imports, err := packageImports(root, mod)
	if err != nil {
		t.Fatalf("packageImports: %v", err)
	}
	from := mod + "/internal/advisor"
	target := mod + "/internal/hostlist"
	if _, ok := imports[from]; !ok {
		t.Fatalf("expected to find package %s in import map; got keys: %v", from, keysSorted(imports))
	}
	if chain := reaches(imports, from, target); chain != nil {
		t.Errorf("alignment §3 violation: %s reaches %s via import chain %s; "+
			"see docs/alignment-principles.md §3 (the LLM does not "+
			"interpret patterns — the engine has already decided that "+
			"question). If the advisor needs match-result data, pass "+
			"it on the Input struct rather than importing the matcher.",
			from, target, strings.Join(chain, " → "))
	}
}

func keysSorted(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
