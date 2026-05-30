package lint

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestAlignmentPrinciple1_AddAllowDenyOnlyInConfigwriteOrTests is
// the structural enforcer for the second half of
// docs/alignment-principles.md §1 (and the structural side of
// #200's invariant 2): every operator-action persist path routes
// list mutations through configwrite.OperatorApprove /
// configwrite.OperatorDeny, never through bare AddAllow / AddDeny.
//
// The bare AddAllow / AddDeny primitives are package-private in
// intent: they leave the pattern on the OPPOSITE list, and a
// follow-up request to the same host hits deny (deny wins) — the
// operator's approve silently no-ops. This is the #194 / #179
// recurrence class. OperatorApprove is the consolidate-then-add
// wrapper.
//
// A failure here means a new caller of configwrite.AddAllow or
// configwrite.AddDeny exists outside the configwrite package and
// outside _test.go files. The fix is to swap the call for
// configwrite.OperatorApprove / OperatorDeny, which preserves the
// add semantics and adds the consolidation step.
//
// Legitimate exceptions: code under internal/configwrite/ may call
// AddAllow / AddDeny directly (OperatorApprove is implemented as
// a wrapper there); test files (_test.go) are exempt because tests
// legitimately exercise the bare primitives for behavior assertions.
func TestAlignmentPrinciple1_AddAllowDenyOnlyInConfigwriteOrTests(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	configwriteDir := filepath.Join(root, "internal", "configwrite")
	roots := []string{
		filepath.Join(root, "internal"),
		filepath.Join(root, "cmd"),
	}
	type violation struct {
		path string
		line int
		sel  string
	}
	var found []violation
	for _, r := range roots {
		err := walkGoFiles(r, false, func(path string, f *ast.File, fset *token.FileSet) error {
			// Skip files inside internal/configwrite — that
			// package owns the primitive.
			if strings.HasPrefix(path, configwriteDir+string(filepath.Separator)) ||
				path == configwriteDir {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel == nil {
					return true
				}
				name := sel.Sel.Name
				if name != "AddAllow" && name != "AddDeny" {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if ident.Name != "configwrite" {
					return true
				}
				pos := fset.Position(sel.Pos())
				found = append(found, violation{
					path: pos.Filename,
					line: pos.Line,
					sel:  name,
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", r, err)
		}
	}
	if len(found) == 0 {
		return
	}
	msg := strings.Builder{}
	msg.WriteString("alignment §1 violation: direct call(s) to configwrite.AddAllow / configwrite.AddDeny\n")
	msg.WriteString("found outside internal/configwrite/ and outside _test.go files.\n")
	msg.WriteString("Route through configwrite.OperatorApprove / configwrite.OperatorDeny instead —\n")
	msg.WriteString("the bare primitives leave the pattern on the OPPOSITE list (deny wins on reload,\n")
	msg.WriteString("silently no-op'ing the operator's action; #179 / #194 class).\n")
	msg.WriteString("See docs/alignment-principles.md §1 and internal/configwrite/configwrite.go\n")
	msg.WriteString("OperatorApprove docstring.\n\n")
	msg.WriteString("Violating callsite(s):\n")
	for _, v := range found {
		rel, rerr := filepath.Rel(repoRootMust(t), v.path)
		display := v.path
		if rerr == nil {
			display = filepath.ToSlash(rel)
		}
		msg.WriteString("  - ")
		msg.WriteString(display)
		msg.WriteString(":")
		msg.WriteString(strconv.Itoa(v.line))
		msg.WriteString("  configwrite.")
		msg.WriteString(v.sel)
		msg.WriteString("(...)\n")
	}
	t.Error(msg.String())
}

func repoRootMust(t *testing.T) string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	return root
}
