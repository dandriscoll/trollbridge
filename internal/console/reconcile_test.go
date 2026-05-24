package console

import (
	"bytes"
	"testing"
)

// TestAddPattern_ReconcilesOppositeList pins #179: approving/allowing a
// pattern that is already on the deny list must remove it from deny (and
// vice versa), so the two lists never both carry it — otherwise deny
// wins on reload and the approve silently does nothing.
func TestAddPattern_ReconcilesOppositeList(t *testing.T) {
	// allow X, then deny→allow reconcile: start with X on deny.
	cfgPath := minimalV2Yaml(t, nil, []string{"GET api.example.com/v1/data"})
	b := &Backend{ConfigPath: cfgPath, LocalOnly: true}

	var buf bytes.Buffer
	b.Execute(&buf, "allow GET api.example.com/v1/data")

	allow, deny := listsOf(t, cfgPath)
	if !contains(allow, "GET api.example.com/v1/data") {
		t.Errorf("pattern not added to allow: %v", allow)
	}
	if contains(deny, "GET api.example.com/v1/data") {
		t.Errorf("approving did not remove the pattern from deny (left on both lists): %v", deny)
	}

	// Symmetric: deny X removes it from allow.
	cfgPath2 := minimalV2Yaml(t, []string{"GET evil.example.com/x"}, nil)
	b2 := &Backend{ConfigPath: cfgPath2, LocalOnly: true}
	var buf2 bytes.Buffer
	b2.Execute(&buf2, "deny GET evil.example.com/x")
	allow2, deny2 := listsOf(t, cfgPath2)
	if !contains(deny2, "GET evil.example.com/x") {
		t.Errorf("pattern not added to deny: %v", deny2)
	}
	if contains(allow2, "GET evil.example.com/x") {
		t.Errorf("denying did not remove the pattern from allow: %v", allow2)
	}
}
