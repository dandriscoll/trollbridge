package tui

import (
	"strings"
	"testing"
)

// TestColorizeURLForRow_HTTPGetsBrown pins #64: plain-HTTP URLs in
// the operator UI are wrapped in a brown 256-color escape; HTTPS and
// CONNECT-style URLs (no scheme prefix) pass through uncolored.
func TestColorizeURLForRow_HTTPGetsBrown(t *testing.T) {
	const brown = "\x1b[38;5;94m"

	if got := colorizeURLForRow("padded     ", "http://example.com/x"); !strings.HasPrefix(got, brown) {
		t.Errorf("http:// URL: %q lacks brown prefix %q", got, brown)
	}
	if got := colorizeURLForRow("padded     ", "https://example.com/x"); strings.Contains(got, brown) {
		t.Errorf("https:// URL got brown wrap: %q", got)
	}
	if got := colorizeURLForRow("api.example.com    ", "api.example.com"); strings.Contains(got, brown) {
		t.Errorf("CONNECT-style URL got brown wrap: %q", got)
	}
}
