package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzYAMLLoad closes #104's "fuzz tests for YAML parsing" bullet.
// config.Load is the operator-controlled entry point; a maliciously
// crafted YAML file (DoS via deep nesting, billion-laughs analogue,
// etc.) must produce an error rather than crash the daemon.
//
// Run: go test -fuzz=FuzzYAMLLoad -fuzztime=30s ./internal/config/
func FuzzYAMLLoad(f *testing.F) {
	seeds := []string{
		"proxy: lo:8080\nmode: default-deny\n",
		"",
		"proxy: lo:8080\n",
		"proxy: lo:8080\nlists:\n  allow:\n    - example.com\n  deny: []\n",
		"\x00\x00\x00\x00",
		"a: b\nc: d\n",
		`{"a":1}`,
		"!!binary 'aGVsbG8='",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, body string) {
		path := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Skip("temp dir unavailable; skip this iteration")
		}
		// The contract is "no panic"; Load is allowed to error on
		// malformed input (and almost always will). We don't assert
		// success — we assert absence of crash.
		_, _ = Load(path)
	})
}
