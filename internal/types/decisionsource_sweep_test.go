package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecisionSource_SweepEveryValueHasATestAssertion is a sweep test
// per GO.md "Completeness for sweep changes": when the set of
// DecisionSource values changes, per-test enumeration only catches
// the cases the test author thought to enumerate — the same set the
// implementer thought to assert. The sweep test asserts the property
// at the directory level: every DecisionSource string value appears
// in at least one *_test.go file as a literal.
//
// Failure shape this prevents: a new DecisionSource is added in
// types.go and the proxy starts emitting it on a specific path; no
// test asserts on its presence; the value drifts through the audit
// log unnoticed for weeks. The sweep test fires the moment a new
// source is added without paired coverage.
func TestDecisionSource_SweepEveryValueHasATestAssertion(t *testing.T) {
	root := findRepoRoot(t)
	testFiles := collectTestFiles(t, root)
	if len(testFiles) == 0 {
		t.Fatal("no *_test.go files found; sweep cannot run")
	}

	for _, src := range AllDecisionSources {
		// Quoted-string literal — bare-symbol references in test
		// helpers (e.g., `types.SourceRule`) also qualify. Either
		// shape is sufficient evidence that the value is asserted
		// against somewhere in the suite.
		literal := `"` + string(src) + `"`
		symbol := decisionSourceSymbolName(src)
		found := false
		for _, path := range testFiles {
			// Skip THIS file — it would self-satisfy via the
			// AllDecisionSources list above.
			if filepath.Base(path) == "decisionsource_sweep_test.go" {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			s := string(data)
			if strings.Contains(s, literal) || strings.Contains(s, symbol) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DecisionSource %q (symbol types.%s) is not referenced by any *_test.go file outside this sweep — add a real test that asserts on it before it drifts through audit unnoticed", string(src), symbol)
		}
	}
}

// TestDecisionSource_SweepListMatchesConstBlock asserts the
// AllDecisionSources list is kept in sync with the const block in
// types.go. The check is intentionally a count comparison, not a
// scan-by-name — the goal is to fire when a const is added or
// removed without updating the sweep list. A maintainer who edits
// types.go's const block must update AllDecisionSources here, which
// then forces them through the sweep above.
func TestDecisionSource_SweepListMatchesConstBlock(t *testing.T) {
	root := findRepoRoot(t)
	typesGo := filepath.Join(root, "internal", "types", "types.go")
	data, err := os.ReadFile(typesGo)
	if err != nil {
		t.Fatalf("read types.go: %v", err)
	}
	src := string(data)
	// Crude but robust: count occurrences of `DecisionSource = "`
	// inside the const block. Matches every const declaration line.
	got := strings.Count(src, "DecisionSource = \"")
	if got != len(AllDecisionSources) {
		t.Errorf("AllDecisionSources length = %d, but types.go has %d `DecisionSource = \"…\"` declarations — keep them in lockstep", len(AllDecisionSources), got)
	}
}

func decisionSourceSymbolName(src DecisionSource) string {
	switch src {
	case SourceRule:
		return "SourceRule"
	case SourceDefault:
		return "SourceDefault"
	case SourceLLMAdvisor:
		return "SourceLLMAdvisor"
	case SourceApprovalQueue:
		return "SourceApprovalQueue"
	case SourceApprovalTimeout:
		return "SourceApprovalTimeout"
	case SourceAllowList:
		return "SourceAllowList"
	case SourceDenyList:
		return "SourceDenyList"
	case SourceTLSHandshakeFail:
		return "SourceTLSHandshakeFail"
	case SourceMalformedTunnel:
		return "SourceMalformedTunnel"
	case SourceBodyReadFail:
		return "SourceBodyReadFail"
	case SourceOpenMode:
		return "SourceOpenMode"
	}
	return string(src)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod ascending from %s", cwd)
	return ""
}

func collectTestFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			// Skip vendor, dist, bin, dot-dirs — none host meaningful test files.
			if name == "vendor" || name == "dist" || name == "bin" || strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}