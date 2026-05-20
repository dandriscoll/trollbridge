package console

import (
	"bytes"
	"strings"
	"testing"
)

// TestBackend_AcceptGeneralization_RemovesSourcesAddsPattern pins #173
// at the console layer: accepting a generalization removes the more-
// specific source entries and adds the pattern, then reloads.
func TestBackend_AcceptGeneralization_RemovesSourcesAddsPattern(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{
		"GET api.example.com/v1/users/123",
		"GET api.example.com/v1/users/456",
		"other.example",
	}, nil)
	reloaded := false
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true, OnReload: func() { reloaded = true }}

	var buf bytes.Buffer
	b.AcceptGeneralization(&buf, "allow", "GET api.example.com/v1/users/*",
		[]string{"GET api.example.com/v1/users/123", "GET api.example.com/v1/users/456"})

	out := buf.String()
	if !strings.Contains(out, "removed 2 specific") {
		t.Errorf("expected removed-count message; got: %s", out)
	}
	if !reloaded {
		t.Errorf("expected reload after accept")
	}
	allow, _ := listsOf(t, cfgPath)
	if !contains(allow, "GET api.example.com/v1/users/*") {
		t.Errorf("pattern not added: %v", allow)
	}
	for _, src := range []string{"GET api.example.com/v1/users/123", "GET api.example.com/v1/users/456"} {
		if contains(allow, src) {
			t.Errorf("specific source %q not removed: %v", src, allow)
		}
	}
	if !contains(allow, "other.example") {
		t.Errorf("unrelated entry removed: %v", allow)
	}
}

// TestBackend_AcceptGeneralization_AttachModeGuarded verifies accept is
// refused in attach mode (no local config to write).
func TestBackend_AcceptGeneralization_AttachModeGuarded(t *testing.T) {
	b := &Backend{ConfigPath: "", LocalOnly: false}
	var buf bytes.Buffer
	b.AcceptGeneralization(&buf, "allow", "x", nil)
	if !strings.Contains(buf.String(), "attach mode") {
		t.Errorf("expected attach-mode guard message; got: %s", buf.String())
	}
}
