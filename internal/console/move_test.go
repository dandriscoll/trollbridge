package console

import (
	"strings"
	"testing"
)

// TestBackend_MoveAllowMigratesFromDeny pins the atomic-move semantics
// of `move allow <pat>` when the pattern currently lives on the deny
// list (the URLs panel 'a' (approve) keystroke path, closes #86).
func TestBackend_MoveAllowMigratesFromDeny(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, []string{"evil.example"})
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "move allow evil.example")
	if !strings.Contains(out, "moved evil.example to allow") {
		t.Errorf("expected 'moved … to allow' confirmation; got: %s", out)
	}
	allow, deny := listsOf(t, cfgPath)
	if !contains(allow, "evil.example") {
		t.Errorf("allow list missing entry after move: %v", allow)
	}
	if contains(deny, "evil.example") {
		t.Errorf("deny list still has entry after move: %v", deny)
	}
}

// TestBackend_MoveDenyMigratesFromAllow mirrors the above for 'd'.
func TestBackend_MoveDenyMigratesFromAllow(t *testing.T) {
	cfgPath := minimalV2Yaml(t, []string{"trusted.example"}, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "move deny trusted.example")
	if !strings.Contains(out, "moved trusted.example to deny") {
		t.Errorf("expected 'moved … to deny' confirmation; got: %s", out)
	}
	allow, deny := listsOf(t, cfgPath)
	if contains(allow, "trusted.example") {
		t.Errorf("allow list still has entry after move: %v", allow)
	}
	if !contains(deny, "trusted.example") {
		t.Errorf("deny list missing entry after move: %v", deny)
	}
}

// TestBackend_MoveAllowOnFreshPatternAdds verifies that `move allow X`
// where X is in neither list simply adds X to allow.
func TestBackend_MoveAllowOnFreshPatternAdds(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "move allow fresh.example")
	if !strings.Contains(out, "added fresh.example to allow") {
		t.Errorf("expected 'added' confirmation; got: %s", out)
	}
}

// TestBackend_MoveRejectsBadSide verifies the usage-string path.
func TestBackend_MoveRejectsBadSide(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "move sideways foo.example")
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage error; got: %s", out)
	}
}

// TestBackend_MoveRejectsBadPattern surfaces invalid patterns the
// same way `allow` / `deny` do.
func TestBackend_MoveRejectsBadPattern(t *testing.T) {
	cfgPath := minimalV2Yaml(t, nil, nil)
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}
	out, _ := runLines(t, b, "move allow api.*.foo")
	if !strings.Contains(out, "invalid pattern") {
		t.Errorf("expected invalid-pattern error; got: %s", out)
	}
}
