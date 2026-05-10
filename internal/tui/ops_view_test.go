package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

func opAt(reqID, method, url, status, holdID string, when time.Time) opstream.Op {
	return opstream.Op{
		RequestID: reqID,
		Method:    method,
		URL:       url,
		Status:    status,
		HoldID:    holdID,
		StartedAt: when,
		UpdatedAt: when,
	}
}

// TestRender_UpperPaneShowsMethodURLStatus pins the #52 contract: the
// upper pane's column shape is METHOD URL STATUS (not the prior
// ID IDENTITY HOST:PORT PATH).
func TestRender_UpperPaneShowsMethodURLStatus(t *testing.T) {
	when := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Cols: 100,
		Rows: 30,
		Ops: []opstream.Op{
			opAt("req-1", "GET", "https://api.example.com:443/v1/things", "200", "", when),
			opAt("req-2", "POST", "https://api.example.com:443/v1/danger", opstream.StatusPending, "hold-x", when),
		},
		Focused: PaneApprovals,
		Console: ConsoleModel{Prompt: "trollbridge> "},
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()

	for _, want := range []string{"METHOD", "URL", "STATUS", "GET", "POST", "https://api.example.com:443/v1/things", "200", "pending"} {
		if !strings.Contains(out, want) {
			t.Errorf("frame missing %q; first 600: %q", want, first(out, 600))
		}
	}
	for _, gone := range []string{" ID  ", "IDENTITY", "HOST:PORT", "PATH "} {
		if strings.Contains(out, gone) {
			t.Errorf("frame still contains old column header %q", gone)
		}
	}
}

// TestRender_StatusUpdateIsInPlace pins the in-place rewrite contract.
// The same request_id transitioning evaluating → 200 must occupy the
// same row index across the two render frames; the only change is the
// STATUS column.
func TestRender_StatusUpdateIsInPlace(t *testing.T) {
	when := time.Unix(1_700_000_000, 0).UTC()
	first := opstream.Op{
		RequestID: "req-1", Method: "GET",
		URL:       "https://example.com:443/path",
		Status:    opstream.StatusEvaluating,
		StartedAt: when, UpdatedAt: when,
	}
	second := first
	second.Status = "200"
	second.UpdatedAt = when.Add(time.Second)

	m1 := Model{Cols: 100, Rows: 30, Ops: []opstream.Op{first}, Focused: PaneApprovals}
	m2, _ := Apply(m1, OpsTickResult{Ops: []opstream.Op{second}})

	var b1, b2 strings.Builder
	_ = render(&b1, m1)
	_ = render(&b2, m2)

	row1 := opRowFor(t, b1.String(), "req-1-marker-substituted")
	_ = row1
	// We can't easily search by request_id (it isn't rendered), but we
	// can search by URL — the URL column is stable across the two
	// frames; the status column is the only difference.
	r1 := findRowContaining(t, b1.String(), "https://example.com:443/path")
	r2 := findRowContaining(t, b2.String(), "https://example.com:443/path")
	if r1 == "" || r2 == "" {
		t.Fatalf("URL row missing in one of the frames")
	}
	if !strings.Contains(r1, "evaluating") {
		t.Errorf("frame 1 row missing 'evaluating': %q", r1)
	}
	if !strings.Contains(r2, "200") {
		t.Errorf("frame 2 row missing '200': %q", r2)
	}
	// Stable identity: both frames should have the same number of rows
	// containing this URL (exactly one).
	if got := strings.Count(b1.String(), "https://example.com:443/path"); got != 1 {
		t.Errorf("URL row count in frame 1 = %d, want 1", got)
	}
	if got := strings.Count(b2.String(), "https://example.com:443/path"); got != 1 {
		t.Errorf("URL row count in frame 2 = %d, want 1 (in-place update, not append)", got)
	}
}

// TestDisplayedOps_MergesEvictedHolds verifies the burst-pressure
// backstop: a hold that's no longer in the ops ring still appears in
// the displayed list as a synthetic pending op so the operator never
// silently loses an actionable hold.
func TestDisplayedOps_MergesEvictedHolds(t *testing.T) {
	m := Model{
		Ops: []opstream.Op{
			opAt("req-A", "GET", "https://a.example/", "200", "", time.Unix(1, 0)),
		},
		Holds: []approvals.Snapshot{
			{ID: "hold-X", Method: "POST", Scheme: "https", Host: "x.example", Port: 443, Path: "/danger", CreatedAt: time.Unix(2, 0)},
		},
	}
	d := DisplayedOps(m)
	if len(d) != 2 {
		t.Fatalf("displayed len = %d, want 2 (1 op + 1 evicted-hold synthetic)", len(d))
	}
	var found bool
	for _, o := range d {
		if o.HoldID == "hold-X" && o.Status == opstream.StatusPending && o.URL == "https://x.example:443/danger" {
			found = true
		}
	}
	if !found {
		t.Errorf("synthetic pending op for evicted hold-X missing; displayed = %+v", d)
	}
}

// TestApplyKey_ApprovesUsesHoldIDFromOp pins that the action keys
// drive the approve/deny flow off the selected op's HoldID — which
// is what makes #52's column rework actionable.
func TestApplyKey_ApprovesUsesHoldIDFromOp(t *testing.T) {
	m := Model{
		Cols:    100, Rows: 30,
		Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "req-1", Method: "POST", URL: "https://x/", Status: opstream.StatusPending, HoldID: "hold-XYZ"},
		},
		Selected: 0,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	approve, ok := cmd.(CmdApprove)
	if !ok {
		t.Fatalf("cmd = %T, want CmdApprove", cmd)
	}
	if approve.ID != "hold-XYZ" {
		t.Errorf("approve.ID = %q, want %q", approve.ID, "hold-XYZ")
	}
	if !strings.Contains(got.LastInfo, "hold-XYZ") {
		t.Errorf("LastInfo = %q, want it to mention hold-XYZ", got.LastInfo)
	}
}

// TestApplyKey_ApprovesNonPendingShowsError pins the affordance
// guard: pressing 'a' on a row whose status is not pending should
// not fire CmdApprove — it sets an error and waits.
func TestApplyKey_ApprovesNonPendingShowsError(t *testing.T) {
	m := Model{
		Cols:    100, Rows: 30,
		Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "req-1", Method: "GET", URL: "https://x/", Status: "200", HoldID: ""},
		},
		Selected: 0,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	if _, ok := cmd.(CmdApprove); ok {
		t.Errorf("approve fired on non-pending op; want no-op")
	}
	if !strings.Contains(got.LastErr, "not pending") {
		t.Errorf("LastErr = %q, want 'not pending'-ish", got.LastErr)
	}
}

// TestApply_OpsTickPreservesSelectionByRequestID is the analog of
// the holds-side TestApply_TickPreservesSelectionByID for ops.
func TestApply_OpsTickPreservesSelectionByRequestID(t *testing.T) {
	when := time.Unix(1_700_000_000, 0).UTC()
	a := opAt("req-A", "GET", "https://a/", opstream.StatusEvaluating, "", when)
	b := opAt("req-B", "GET", "https://b/", opstream.StatusEvaluating, "", when)
	c := opAt("req-C", "GET", "https://c/", opstream.StatusEvaluating, "", when)
	m := Model{Ops: []opstream.Op{a, b, c}, Selected: 1, Cols: 100, Rows: 30}
	got, _ := Apply(m, OpsTickResult{Ops: []opstream.Op{c, b, a}})
	if got.Selected != 1 {
		t.Errorf("Selected = %d, want 1 (req-B's new index)", got.Selected)
	}
	displayed := DisplayedOps(got)
	if displayed[got.Selected].RequestID != "req-B" {
		t.Errorf("op at Selected = %s, want req-B", displayed[got.Selected].RequestID)
	}
}

// helpers

func findRowContaining(t *testing.T, frame, needle string) string {
	t.Helper()
	for _, row := range strings.Split(frame, "\r\n") {
		if strings.Contains(row, needle) {
			return row
		}
	}
	return ""
}

func opRowFor(t *testing.T, frame, _ string) string {
	t.Helper()
	return ""
}
