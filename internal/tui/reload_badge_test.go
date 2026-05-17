package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/reloadstatus"
)

// TestApplyReloadTick_PopulatesModelOnFailure pins the reducer step
// for #129: a ReloadTickResult carrying a non-empty Status.LastError
// flips Model.ReloadStatus.LastError to that value. The approvals-
// pane renderer reads it directly to drive the badge.
func TestApplyReloadTick_PopulatesModelOnFailure(t *testing.T) {
	now := time.Now().UTC()
	got, _ := Apply(Model{}, ReloadTickResult{
		Status: reloadstatus.Status{
			LastError:  "bad yaml at line 7",
			LastAt:     now,
			LastSource: "rules",
		},
	})
	if got.ReloadStatus.LastError != "bad yaml at line 7" {
		t.Errorf("ReloadStatus.LastError = %q, want %q", got.ReloadStatus.LastError, "bad yaml at line 7")
	}
	if got.ReloadStatus.LastSource != "rules" {
		t.Errorf("ReloadStatus.LastSource = %q, want %q", got.ReloadStatus.LastSource, "rules")
	}
}

// TestApplyReloadTick_ClearsOnSuccess pins the transition from
// badge-on to badge-off when the operator fixes the file: a
// successful follow-up reload (Status.LastError == "") replaces the
// model's prior failure with a clean snapshot.
func TestApplyReloadTick_ClearsOnSuccess(t *testing.T) {
	prior := Model{
		ReloadStatus: reloadstatus.Status{
			LastError:  "prior failure",
			LastAt:     time.Now().UTC().Add(-time.Second),
			LastSource: "rules",
		},
	}
	now := time.Now().UTC()
	got, _ := Apply(prior, ReloadTickResult{
		Status: reloadstatus.Status{
			LastError:  "",
			LastAt:     now,
			LastSource: "config",
		},
	})
	if got.ReloadStatus.LastError != "" {
		t.Errorf("after success: LastError = %q, want empty", got.ReloadStatus.LastError)
	}
	if got.ReloadStatus.LastSource != "config" {
		t.Errorf("after success: LastSource = %q, want %q", got.ReloadStatus.LastSource, "config")
	}
}

// TestApplyReloadTick_KeepsPriorOnTransportError pins the design's
// dependability decision: a network blip on the /v1/rules poll
// (Err != nil) must NOT flip the badge state. The prior status
// stays, the renderer keeps showing what was true at the last
// successful poll.
func TestApplyReloadTick_KeepsPriorOnTransportError(t *testing.T) {
	prior := Model{
		ReloadStatus: reloadstatus.Status{
			LastError:  "prior failure",
			LastAt:     time.Now().UTC().Add(-time.Second),
			LastSource: "rules",
		},
	}
	got, _ := Apply(prior, ReloadTickResult{
		Status: reloadstatus.Status{}, // empty — would mean "no reload yet"
		Err:    errTransport{},
	})
	if got.ReloadStatus.LastError != "prior failure" {
		t.Errorf("transport blip should not clear the badge; LastError = %q, want %q",
			got.ReloadStatus.LastError, "prior failure")
	}
}

// errTransport is a sentinel error used to drive the transport-blip
// path through the reducer without depending on a specific error
// type.
type errTransport struct{}

func (errTransport) Error() string { return "transport: blip" }
