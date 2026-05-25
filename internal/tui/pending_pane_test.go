package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestOpsPendingSplit pins that the split index equals the resolved
// count: DisplayedOps orders [resolved... | pending...].
func TestOpsPendingSplit(t *testing.T) {
	m := manyOpsWithPending()
	d := DisplayedOps(m)
	split := opsPendingSplit(d)
	if split != 30 {
		t.Fatalf("split = %d, want 30 (resolved count)", split)
	}
	for i := split; i < len(d); i++ {
		if opIsResolved(d[i].Status) {
			t.Errorf("row %d after split is resolved; tail must be all pending", i)
		}
	}
}

// TestRender_PendingPinnedWhileCursorInResolved is the discriminating
// #185 test. With the cursor in the resolved region near the top AND
// far more resolved ops than fit, the OLD bottom-anchored scroll
// followed the cursor up and pushed pending off-screen (the #175 I-3
// caveat). The pinned pending card must keep BOTH the selected resolved
// row and the pending rows visible at once.
func TestRender_PendingPinnedWhileCursorInResolved(t *testing.T) {
	m := manyOpsWithPending()
	d := DisplayedOps(m)
	m.Selected = 1 // a resolved row near the top of the list
	selectedURL := d[1].URL

	for _, tc := range []struct {
		name   string
		render func(*strings.Builder, Model, int)
	}{
		{"bordered", renderApprovalsPane},
		{"no-border", renderApprovalsPaneNoBorder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			tc.render(&b, m, m.Rows)
			out := b.String()
			if !strings.Contains(out, selectedURL) {
				t.Errorf("selected resolved row %q not visible:\n%s", selectedURL, out)
			}
			for _, host := range []string{"pendingalpha.example", "pendingbravo.example"} {
				if !strings.Contains(out, host) {
					t.Errorf("pending %q scrolled off while cursor in resolved — not pinned:\n%s", host, out)
				}
			}
		})
	}
}

// TestRender_PendingCardHeaderPresent pins that the pending tail renders
// as its own labelled card region (not merged into the scroll list).
func TestRender_PendingCardHeaderPresent(t *testing.T) {
	m := manyOpsWithPending()
	var b strings.Builder
	renderApprovalsPane(&b, m, m.Rows)
	if !strings.Contains(b.String(), "pending (2)") {
		t.Errorf("pending card header %q not found:\n%s", "pending (2)", b.String())
	}
}

// TestCursor_CrossesIntoAndOutOfPending pins the #185 cursor contract:
// moving down past the last resolved row enters the pending region, and
// moving up off the first pending row returns to the resolved list. The
// operator must scroll all the way to the bottom to re-enter pending.
func TestCursor_CrossesIntoAndOutOfPending(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			opAt("r1", "GET", "https://a/", "200", "", t0),
			opAt("r2", "GET", "https://b/", "200", "", t0.Add(time.Second)),
		},
		Holds: []approvals.Snapshot{
			{ID: "hold-A", Method: "POST", Scheme: "https", Host: "p1", Port: 443, Path: "/", CreatedAt: t0.Add(100 * time.Second)},
		},
	}
	d := DisplayedOps(m)
	split := opsPendingSplit(d)
	if split < 1 || split >= len(d) {
		t.Fatalf("unexpected split %d for %d rows", split, len(d))
	}

	// Cursor on the last resolved row; Down enters pending.
	m.Selected = split - 1
	got, _ := Apply(m, KeyEvent{Key: KeyDown})
	if got.Selected != split {
		t.Fatalf("Down from last resolved: Selected = %d, want %d (first pending)", got.Selected, split)
	}
	if opIsResolved(d[got.Selected].Status) {
		t.Errorf("after Down the selected row is resolved, expected pending")
	}

	// Cursor on the first pending row; Up returns to the resolved list.
	m.Selected = split
	got, _ = Apply(m, KeyEvent{Key: KeyUp})
	if got.Selected != split-1 {
		t.Fatalf("Up from first pending: Selected = %d, want %d (last resolved)", got.Selected, split-1)
	}
	if !opIsResolved(d[got.Selected].Status) {
		t.Errorf("after Up the selected row is pending, expected resolved")
	}
}
