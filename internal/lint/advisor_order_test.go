package lint

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"testing"
)

// TestAlignmentPrinciple2_AdvisorCalledOnlyFromHoldDispatch is the
// structural enforcer for docs/alignment-principles.md §2: the LLM
// is consulted only when the deterministic engine has already
// established that the request does not match any list pattern.
//
// The structural property: the only callsite of
// `<receiver>.advisor.Classify(...)` inside internal/server/ is in
// the body of `consultAdvisorForHold`. consultAdvisorForHold is
// itself called only from the dispatch path's
// EffectAskUser/EffectAskLLM gate (verified by behavior tests in
// internal/server/server_test.go and refusal_test.go); the two-hop
// invariant gives §2 its structural shape.
//
// A failure here means a recent commit added a call to
// `advisor.Classify` from somewhere other than consultAdvisorForHold
// — for example, a "pre-check" call from the fast-path or a
// "second-opinion" call from a different handler. The fix is to
// route the call through consultAdvisorForHold (and the
// EffectAskUser/EffectAskLLM gate), or to surface a §2 redesign
// for explicit review.
func TestAlignmentPrinciple2_AdvisorCalledOnlyFromHoldDispatch(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	serverDir := filepath.Join(root, "internal", "server")
	type call struct {
		file string
		line int
		fn   string // enclosing function name
	}
	var calls []call
	err = walkGoFiles(serverDir, false, func(path string, f *ast.File, fset *token.FileSet) error {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "Classify" {
					return true
				}
				// Match `<receiver>.advisor.Classify(...)` — sel.X is
				// the `<receiver>.advisor` selector. We accept any
				// chain ending in `.advisor.Classify`.
				inner, ok := sel.X.(*ast.SelectorExpr)
				if !ok || inner.Sel == nil || inner.Sel.Name != "advisor" {
					return true
				}
				pos := fset.Position(ce.Pos())
				calls = append(calls, call{
					file: pos.Filename,
					line: pos.Line,
					fn:   fn.Name.Name,
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk server: %v", err)
	}
	if len(calls) == 0 {
		t.Fatalf("found zero advisor.Classify callsites in internal/server/ — "+
			"the test depends on at least one (consultAdvisorForHold). "+
			"If advisor consultation has moved out of internal/server entirely, "+
			"update this test to walk the new location, or surface the "+
			"§2 invariant in the new location's package.")
	}
	for _, c := range calls {
		if c.fn != "consultAdvisorForHold" {
			rel, rerr := filepath.Rel(root, c.file)
			display := c.file
			if rerr == nil {
				display = filepath.ToSlash(rel)
			}
			t.Errorf("alignment §2 violation: advisor.Classify called at %s:%d "+
				"inside function %s — outside consultAdvisorForHold; see "+
				"docs/alignment-principles.md §2 (the advisor is consulted "+
				"only after the engine returns EffectAskUser / EffectAskLLM). "+
				"Route the call through consultAdvisorForHold or surface a §2 "+
				"redesign explicitly.",
				display, c.line, c.fn)
		}
	}
}

