package selfdescribe

import (
	"os"
	"testing"
)

// TestEmbed_NoDriftWithRepoRoot guards against the embed copies in
// internal/selfdescribe/ falling out of sync with the human-read
// authoritative copies at repo root. If you edit one, copy to the
// other; this test fails the build otherwise.
func TestEmbed_NoDriftWithRepoRoot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		root     string
		embedded []byte
	}{
		{"PROXIED-AGENT.md", "../../PROXIED-AGENT.md", proxiedAgentMD},
		{"CLIENT-SETUP-AGENT.md", "../../CLIENT-SETUP-AGENT.md", clientSetupMD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repoBytes, err := os.ReadFile(tc.root)
			if err != nil {
				t.Fatalf("read %s: %v", tc.root, err)
			}
			if string(repoBytes) != string(tc.embedded) {
				t.Errorf("embedded %s drifted from repo-root copy at %s\n"+
					"fix: cp %s internal/selfdescribe/",
					tc.name, tc.root, tc.root)
			}
		})
	}
}
