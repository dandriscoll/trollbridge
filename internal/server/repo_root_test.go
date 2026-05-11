package server_test

import (
	"os"
	"path/filepath"
	"testing"
)

// findRepoRoot walks up from the test's CWD until it sees go.mod.
// Cross-platform. Used by subprocess tests (POSIX-gated) and by the
// sweep test (cross-platform).
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
	t.Fatalf("could not find repo root from %s", cwd)
	return ""
}
