// Package lint implements AST-based structural checks that pin
// load-bearing invariants from docs/alignment-principles.md. Each
// check runs as a standard `go test` under this package, so the
// existing CI matrix (ubuntu, windows, macos via .github/workflows/ci.yml)
// exercises them on every PR without new tooling.
//
// New principles or invariants add a test here; the principle text
// in docs/alignment-principles.md names the test, the test comment
// names the principle (closes #200, #201; recurrence-prevention for
// #193, #194).
package lint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// repoRoot walks up from the test's working directory until it finds
// a go.mod file. Tests run from their package directory (e.g.
// internal/lint/), so the walk normally takes a couple of hops.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found walking up from cwd")
		}
		dir = parent
	}
}

// modulePath returns the Go module path from go.mod (the first line
// matching `^module <path>`). Used to identify in-module imports
// during transitive-import walks.
func modulePath(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "module ")), nil
		}
	}
	return "", fmt.Errorf("module declaration not found in go.mod")
}

// walkGoFiles invokes fn for every non-test .go file under root,
// excluding vendor/ and .git/. The parsed *ast.File is provided so
// callers can both walk imports and walk callsites without re-parsing.
func walkGoFiles(root string, includeTests bool, fn func(path string, file *ast.File, fset *token.FileSet) error) error {
	fset := token.NewFileSet()
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == "vendor" || base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		return fn(path, f, fset)
	})
}

// packageImports walks the source tree rooted at root and returns
// a map: package import path → set of package import paths it
// directly imports. Only packages whose path starts with mod (the
// module path) appear as keys; imports outside the module are
// recorded as values (so a caller can detect any path that leaves
// the module) but are not themselves walked. Test files are
// excluded — alignment-principle invariants apply to production
// builds, and a test fixture that legitimately exercises a
// configwrite primitive should not be policed as an import-graph
// violation.
func packageImports(root, mod string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	roots := []string{
		filepath.Join(root, "internal"),
		filepath.Join(root, "cmd"),
	}
	for _, r := range roots {
		err := walkGoFiles(r, false, func(path string, f *ast.File, _ *token.FileSet) error {
			pkgDir := filepath.Dir(path)
			rel, rerr := filepath.Rel(root, pkgDir)
			if rerr != nil {
				return rerr
			}
			pkg := mod + "/" + filepath.ToSlash(rel)
			set := out[pkg]
			if set == nil {
				set = map[string]bool{}
				out[pkg] = set
			}
			for _, imp := range f.Imports {
				// imp.Path.Value is the quoted string literal.
				if len(imp.Path.Value) < 2 {
					continue
				}
				ip := imp.Path.Value[1 : len(imp.Path.Value)-1]
				set[ip] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// reaches performs a DFS over the import map starting from `from`,
// returning the import-path chain (inclusive) if `target` is
// reachable, or nil if not. The chain is the first one DFS finds —
// sufficient for a failure message, not guaranteed to be the
// shortest.
func reaches(imports map[string]map[string]bool, from, target string) []string {
	visited := map[string]bool{}
	var dfs func(node string, path []string) []string
	dfs = func(node string, path []string) []string {
		if visited[node] {
			return nil
		}
		visited[node] = true
		next := append(append([]string{}, path...), node)
		if node == target {
			return next
		}
		for dep := range imports[node] {
			if dep == target {
				return append(next, dep)
			}
			// Only walk in-module deps (we don't have third-party
			// imports parsed); third-party packages cannot import
			// our internal packages anyway.
			if _, present := imports[dep]; present {
				if chain := dfs(dep, next); chain != nil {
					return chain
				}
			}
		}
		return nil
	}
	return dfs(from, nil)
}
