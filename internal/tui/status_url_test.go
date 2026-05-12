package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyActionResult_LastInfoUsesURL pins #92: the action-result
// status string names the method+URL of the resolved op, not the
// hold id.
func TestApplyActionResult_LastInfoUsesURL(t *testing.T) {
	m := Model{
		Ops: []opstream.Op{
			{Method: "POST", URL: "https://api.example.com/", Status: opstream.StatusPending, HoldID: "hold-1"},
		},
	}
	got, _ := Apply(m, ActionResult{ID: "hold-1", Action: "approve"})
	if !strings.Contains(got.LastInfo, "POST https://api.example.com/") {
		t.Errorf("LastInfo = %q, want it to contain method+URL", got.LastInfo)
	}
	if strings.Contains(got.LastInfo, "hold-1") {
		t.Errorf("LastInfo still mentions hold id: %q", got.LastInfo)
	}
}

// TestApplyActionResult_LastInfoFallbackOnEvictedOp pins the
// fallback path: if the op is no longer in the ring, the message
// degrades gracefully (no bare hold id).
func TestApplyActionResult_LastInfoFallbackOnEvictedOp(t *testing.T) {
	m := Model{Ops: nil}
	got, _ := Apply(m, ActionResult{ID: "hold-gone", Action: "approve"})
	if strings.Contains(got.LastInfo, "hold-gone") {
		t.Errorf("LastInfo = %q surfaces hold id when op evicted", got.LastInfo)
	}
	if got.LastInfo == "" {
		t.Errorf("LastInfo empty; want fallback text")
	}
}

// TestRenderInfoPane_DropsRequestIDRow pins that #92's removal of
// the request_id row from the info pane took effect.
func TestRenderInfoPane_DropsRequestIDRow(t *testing.T) {
	m := infoModel(opstream.Op{
		RequestID: "req-abc", Method: "GET", URL: "https://x/",
		Status: "200",
	}, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b.String(), "request_id") {
		t.Errorf("info pane still contains 'request_id' row")
	}
}
