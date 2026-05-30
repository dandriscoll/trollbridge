package lint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestAlignmentPrinciple4_NoApplicationIdentifiersInWireStrings is
// the structural enforcer for docs/alignment-principles.md §4: the
// LLM provider sees nothing that names trollbridge, describes its
// role as a proxy, or identifies its purpose as gating an AI agent.
//
// The check inspects string constants in
// internal/advisor/prompts.go and internal/advisor/translator.go
// that are wire-bound (composed into the system prompt or sent as
// the tool name/description). A failure means a recent commit
// introduced one of the forbidden tokens — "trollbridge", "proxy",
// "gateway", "egress controller" — into a constant the LLM will
// see. Fix by rephrasing in generic classifier terms.
//
// Scope notes:
//   - Internal Go identifiers and comments are exempt. The check
//     reads only the values of string LITERAL constants, not
//     identifier names or surrounding doc text.
//   - "egress" alone is not banned — it has legitimate uses in
//     operator-supplied directives (configurable at runtime, not a
//     constant). The banned phrase is the specific role-naming form
//     "egress controller".
//   - Computed expressions (string concatenations, fmt-format
//     templates) are not analyzed — if a wire-bound string becomes
//     computed in the future, extend this check.
func TestAlignmentPrinciple4_NoApplicationIdentifiersInWireStrings(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	files := []string{
		filepath.Join(root, "internal", "advisor", "prompts.go"),
		filepath.Join(root, "internal", "advisor", "translator.go"),
	}
	// Wire-bound constants by name. Adding a new wire-bound
	// constant in either file means adding it here.
	wireBound := map[string]bool{
		"baselineReview":   true,
		"baselineResearch": true,
		"toolName":         true,
		"toolDescription":  true,
	}
	forbidden := []string{
		"trollbridge",
		"proxy",
		"gateway",
		"egress controller",
	}
	fset := token.NewFileSet()
	inspected := map[string]bool{}
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !wireBound[name.Name] {
						continue
					}
					inspected[name.Name] = true
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("alignment §4 enforcement gap: constant %s in %s "+
							"is not a plain string literal — the lint check cannot "+
							"inspect computed wire-bound strings. Extend "+
							"TestAlignmentPrinciple4_NoApplicationIdentifiersInWireStrings "+
							"to walk the new expression shape.",
							name.Name, filepath.Base(path))
						continue
					}
					value := strings.ToLower(litValue(lit.Value))
					for _, tok := range forbidden {
						if strings.Contains(value, tok) {
							t.Errorf("alignment §4 violation: wire-bound constant %s "+
								"in %s contains forbidden token %q; see "+
								"docs/alignment-principles.md §4 (the LLM provider "+
								"must see nothing that names the application). Rephrase "+
								"in generic classifier terms.",
								name.Name, filepath.Base(path), tok)
						}
					}
				}
			}
		}
	}
	// Sanity check: if zero wire-bound constants were inspected,
	// the test would have passed vacuously — likely because the
	// constants were renamed and `wireBound` was not updated. Fail
	// loudly so the maintainer adds the new names.
	if len(inspected) == 0 {
		t.Errorf("alignment §4 enforcement gap: the wireBound name set " +
			"matched no constants in internal/advisor/prompts.go or " +
			"internal/advisor/translator.go — the test ran against zero " +
			"constants and proved nothing. The wire-bound constants " +
			"were likely renamed; update wireBound in this test to match.")
	}
}

// litValue unquotes a Go string-literal token value. Handles the
// three quote shapes used in this codebase: backtick raw strings,
// double-quoted interpreted strings (which may carry escape
// sequences — for substring matching we accept the literal escape
// form because the forbidden tokens contain no escapable
// characters). Defensive: returns the input unchanged if it does
// not appear to be a quoted literal.
func litValue(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '`' && last == '`') || (first == '"' && last == '"') {
		return s[1 : len(s)-1]
	}
	return s
}
