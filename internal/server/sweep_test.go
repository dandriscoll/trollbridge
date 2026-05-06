package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSweep_NoStaleStdlibLoggerCallSites is the structural-test
// closure for job 039: after the migration from `*log.Logger` to
// `*slog.Logger`, no production source file should reference the
// old `s.logger` field name OR import "log" (the stdlib package
// distinct from "log/slog"). The audit-architect calls this kind
// of assertion the "sweep the rendered output" closure for sweep
// changes — it catches the missed call site that per-test specs
// cannot reach.
//
// The test inspects the source tree, not test files, so it does
// not constrain test fixtures that legitimately hold stale-shaped
// fixtures.
func TestSweep_NoStaleStdlibLoggerCallSites(t *testing.T) {
	repo := findRepoRoot(t)
	bannedTokens := map[string]string{
		`s.logger.`:    "operational logger field renamed to opLog and migrated to slog",
		"\t\"log\"\n":  "stdlib log package replaced by log/slog (use the slog import)",
		`*log.Logger`:  "type *log.Logger replaced by *slog.Logger",
		` log.New(`:    "log.New construction replaced by oplog.New",
	}
	checkDirs := []string{"internal", "cmd"}
	for _, root := range checkDirs {
		err := filepath.Walk(filepath.Join(repo, root), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(data)
			for tok, why := range bannedTokens {
				if strings.Contains(content, tok) {
					t.Errorf("%s contains banned token %q (%s)", path, tok, why)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
