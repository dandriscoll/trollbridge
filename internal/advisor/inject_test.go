package advisor

import (
	"fmt"
	"testing"
)

// TestNew_InjectsSyntheticDigestsFromEnv verifies the
// TROLLBRIDGE_TEST_INJECT_DIGESTS env hook: setting the env to a
// positive integer N causes advisor.New to pre-fill the digest
// ring with N deterministic synthetic digests. Pinned the load-
// bearing primitive that the subprocess pty test for #160 depends
// on; a regression here breaks that test silently (the pty test
// would skip on no-digests with no obvious diagnostic).
func TestNew_InjectsSyntheticDigestsFromEnv(t *testing.T) {
	t.Setenv("TROLLBRIDGE_TEST_INJECT_DIGESTS", "5")
	svc := New(Config{}, nil)
	got := svc.Digests().Snapshot()
	if len(got) != 5 {
		t.Fatalf("digest ring length = %d, want 5; entries=%+v", len(got), got)
	}
	for i, d := range got {
		wantHost := fmt.Sprintf("synth-host-%03d.example", i+1)
		if d.Host != wantHost {
			t.Errorf("digest[%d].Host = %q, want %q", i, d.Host, wantHost)
		}
		wantReqID := fmt.Sprintf("synth-req-%03d", i+1)
		if d.RequestID != wantReqID {
			t.Errorf("digest[%d].RequestID = %q, want %q", i, d.RequestID, wantReqID)
		}
		if d.Effect != "allow" {
			t.Errorf("digest[%d].Effect = %q, want \"allow\"", i, d.Effect)
		}
		if d.Outcome != DigestOutcomeClassified {
			t.Errorf("digest[%d].Outcome = %q, want %q", i, d.Outcome, DigestOutcomeClassified)
		}
	}
	// Newest-first ordering (m.Digests[len-1] is newest by insertion
	// order) — the property the TUI's reducer assumes.
	if got[len(got)-1].Host != "synth-host-005.example" {
		t.Errorf("ring last = %q, want \"synth-host-005.example\" (newest)", got[len(got)-1].Host)
	}
}

// TestNew_SkipsInjectionWhenEnvAbsent verifies the default path is
// untouched: no env var set, ring is empty.
func TestNew_SkipsInjectionWhenEnvAbsent(t *testing.T) {
	t.Setenv("TROLLBRIDGE_TEST_INJECT_DIGESTS", "")
	svc := New(Config{}, nil)
	if got := svc.Digests().Snapshot(); len(got) != 0 {
		t.Errorf("ring should be empty when env unset; got %d entries", len(got))
	}
}

// TestNew_SkipsInjectionOnInvalidEnv verifies cautious parse
// behavior: garbage values silently no-op rather than panicking.
func TestNew_SkipsInjectionOnInvalidEnv(t *testing.T) {
	for _, v := range []string{"garbage", "-3", "0", " "} {
		t.Run(fmt.Sprintf("value=%q", v), func(t *testing.T) {
			t.Setenv("TROLLBRIDGE_TEST_INJECT_DIGESTS", v)
			svc := New(Config{}, nil)
			if got := svc.Digests().Snapshot(); len(got) != 0 {
				t.Errorf("ring should be empty for invalid value %q; got %d entries", v, len(got))
			}
		})
	}
}
