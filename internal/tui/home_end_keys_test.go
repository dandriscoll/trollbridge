package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyKeyApprovals_HomeJumpsToFirst pins the #196 invariant
// for the operations pane: Home jumps the cursor to row 0.
func TestApplyKeyApprovals_HomeJumpsToFirst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			opAt("a", "GET", "https://a.example/", "200", "", t0),
			opAt("b", "GET", "https://b.example/", "200", "", t0.Add(time.Second)),
			opAt("c", "GET", "https://c.example/", "200", "", t0.Add(2*time.Second)),
		},
		Selected: 2,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyHome})
	if got.Selected != 0 {
		t.Errorf("after Home: Selected = %d, want 0", got.Selected)
	}
}

// TestApplyKeyApprovals_EndJumpsToLast pins #196 for End.
func TestApplyKeyApprovals_EndJumpsToLast(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			opAt("a", "GET", "https://a.example/", "200", "", t0),
			opAt("b", "GET", "https://b.example/", "200", "", t0.Add(time.Second)),
			opAt("c", "GET", "https://c.example/", "200", "", t0.Add(2*time.Second)),
		},
		Selected: 0,
	}
	want := len(DisplayedOps(m)) - 1
	got, _ := Apply(m, KeyEvent{Key: KeyEnd})
	if got.Selected != want {
		t.Errorf("after End: Selected = %d, want %d", got.Selected, want)
	}
}

// TestApplyKeyApprovals_HomeOnEmptyListIsSafe pins that Home/End
// on an empty operations list do not panic and leave Selected
// at -1 (the empty-list convention).
func TestApplyKeyApprovals_HomeOnEmptyListIsSafe(t *testing.T) {
	m := Model{Selected: -1}
	got, _ := Apply(m, KeyEvent{Key: KeyHome})
	if got.Selected != -1 {
		t.Errorf("Home on empty list: Selected = %d, want -1", got.Selected)
	}
	got, _ = Apply(m, KeyEvent{Key: KeyEnd})
	if got.Selected != -1 {
		t.Errorf("End on empty list: Selected = %d, want -1", got.Selected)
	}
}

// TestApplyKeyURLs_HomeAndEndJumpAcrossList pins #196 for the
// URLs pane: Home jumps to the first allow entry; End jumps to
// the last deny entry (the URLs pane shows allow then deny).
func TestApplyKeyURLs_HomeAndEndJumpAcrossList(t *testing.T) {
	m := Model{
		AllowList:       []string{"a.example", "b.example"},
		DenyList:        []string{"d.example", "e.example"},
		URLsSelected:    2,
		URLsAnchor:      -1,
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelURLs,
		Focused:         PaneConsole,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyHome})
	if got.URLsSelected != 0 {
		t.Errorf("URLs Home: URLsSelected = %d, want 0", got.URLsSelected)
	}
	got, _ = Apply(m, KeyEvent{Key: KeyEnd})
	combined := len(m.AllowList) + len(m.DenyList)
	if got.URLsSelected != combined-1 {
		t.Errorf("URLs End: URLsSelected = %d, want %d", got.URLsSelected, combined-1)
	}
}

// TestApplyKeyLLM_HomeJumpsToFirstDigest pins #196 for the LLM
// pane: Home selects the first digest (per the existing j/k
// orientation, Up moves toward newer; the digest order is
// reversed in the renderer, so the "first" displayed digest is
// the newest).
func TestApplyKeyLLM_HomeJumpsToFirstDigest(t *testing.T) {
	m := Model{
		Digests: []advisor.Digest{
			{RequestID: "req-a"},
			{RequestID: "req-b"},
			{RequestID: "req-c"},
		},
		DigestSelected:  "req-b",
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelLLM,
		Focused:         PaneConsole,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyHome})
	// The first displayed digest is at display index 0; assert the
	// selected RequestID matches whatever digestAtDisplayIndex(0)
	// produces (the renderer's orientation).
	if d, ok := digestAtDisplayIndex(m, 0); ok {
		if got.DigestSelected != d.RequestID {
			t.Errorf("LLM Home: DigestSelected = %q, want %q (display index 0)",
				got.DigestSelected, d.RequestID)
		}
	} else {
		t.Fatal("digestAtDisplayIndex(0) returned ok=false on a 3-entry ring")
	}
}

// TestApplyKeyLLM_EndJumpsToLastDigest pins #196 for End on LLM.
func TestApplyKeyLLM_EndJumpsToLastDigest(t *testing.T) {
	m := Model{
		Digests: []advisor.Digest{
			{RequestID: "req-a"},
			{RequestID: "req-b"},
			{RequestID: "req-c"},
		},
		DigestSelected:  "req-b",
		BottomPanelOpen: true,
		BottomPanel:     BottomPanelLLM,
		Focused:         PaneConsole,
	}
	got, _ := Apply(m, KeyEvent{Key: KeyEnd})
	last := len(m.Digests) - 1
	if d, ok := digestAtDisplayIndex(m, last); ok {
		if got.DigestSelected != d.RequestID {
			t.Errorf("LLM End: DigestSelected = %q, want %q (display index %d)",
				got.DigestSelected, d.RequestID, last)
		}
	} else {
		t.Fatalf("digestAtDisplayIndex(%d) returned ok=false", last)
	}
}

// Reference imports avoid the "imported and not used" lint when only
// some of the test fixtures use them.
var _ = approvals.Snapshot{}
