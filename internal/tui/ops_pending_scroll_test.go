package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// manyOpsWithPending builds a model with more resolved ops than fit the
// body plus two pending holds. DisplayedOps puts the pending rows at the
// bottom of the slice, so a top-anchored render truncates them off-screen.
func manyOpsWithPending() Model {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	var ops []opstream.Op
	for i := 0; i < 30; i++ {
		ops = append(ops, opAt("req-"+itoaPort(i), "GET",
			"https://resolved-"+itoaPort(i)+".example/x", "200", "",
			t0.Add(time.Duration(i)*time.Second)))
	}
	return Model{
		Cols:    100,
		Rows:    12, // small: bodyLines = 9, far fewer than 30+2 rows
		Focused: PaneApprovals,
		Ops:     ops,
		Holds: []approvals.Snapshot{
			{ID: "hold-A", Method: "POST", Scheme: "https", Host: "pendingalpha.example", Port: 443, Path: "/", CreatedAt: t0.Add(100 * time.Second)},
			{ID: "hold-B", Method: "POST", Scheme: "https", Host: "pendingbravo.example", Port: 443, Path: "/", CreatedAt: t0.Add(200 * time.Second)},
		},
		Selected: -1, // resting state (no manual navigation); idle would snap to pending
	}
}

// TestRender_PendingVisibleWhenOpsOverflow pins #175: when the ops list
// overflows the pane, the pending rows (always at the bottom of
// DisplayedOps) must still be rendered, not pushed off-screen.
func TestRender_PendingVisibleWhenOpsOverflow(t *testing.T) {
	m := manyOpsWithPending()

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
			for _, host := range []string{"pendingalpha.example", "pendingbravo.example"} {
				if !strings.Contains(out, host) {
					t.Errorf("pending host %q not visible when ops overflow:\n%s", host, out)
				}
			}
		})
	}
}

// TestRender_CursorVisibleWhenScrolledUp pins SC2: navigating the cursor
// up into the resolved region keeps the selected row visible (the window
// follows the cursor up off the bottom-anchored default).
func TestRender_CursorVisibleWhenScrolledUp(t *testing.T) {
	m := manyOpsWithPending()
	d := DisplayedOps(m)
	m.Selected = 1 // a resolved row near the top
	selectedURL := d[1].URL

	var b strings.Builder
	renderApprovalsPane(&b, m, m.Rows)
	if !strings.Contains(b.String(), selectedURL) {
		t.Errorf("selected row %q not visible after scrolling up:\n%s", selectedURL, b.String())
	}
}
