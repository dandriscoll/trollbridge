package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// pendingOp builds an Op that represents a real in-flight request the
// daemon is holding for operator approval. Pre-#191 reproductions
// require BOTH a RequestID and a HoldID — synthesized pending ops
// (from `m.Holds` only) carry an empty RequestID and produce a
// `h\x00<HoldID>` GroupKey, which silently dodges the by-RequestID
// branch in preserveSelection. Real ops always carry a RequestID, so
// the by-RequestID branch is the one that fires in production, and
// that branch is the one that lets the cursor follow a resolving op
// into the resolved section.
func pendingOp(reqID, holdID, host string, when time.Time) opstream.Op {
	return opstream.Op{
		RequestID: reqID,
		Method:    "GET",
		URL:       "https://" + host + "/",
		Status:    opstream.StatusPending,
		HoldID:    holdID,
		StartedAt: when,
		UpdatedAt: when,
	}
}

func holdSnap(id, host string, when time.Time) approvals.Snapshot {
	return approvals.Snapshot{
		ID:        id,
		Method:    "GET",
		Scheme:    "https",
		Host:      host,
		Port:      443,
		Path:      "/",
		CreatedAt: when,
	}
}

// TestApplyOpsTick_CursorStaysOnPendingWhenSelectedResolves pins
// the #191 invariant for the ops-tick path: when the selected
// pending row's op transitions to a resolved status in the next
// ops tick, the cursor must remain on a pending row. Only an
// explicit Up keystroke may move the cursor off pending.
//
// Pre-fix behavior: preserveSelection's RequestID branch finds the
// now-resolved op (same RequestID, new Status) and the cursor
// follows it into the resolved section.
// Post-fix behavior: section affinity in preserveSelection rejects
// the cross-region match and routes the cursor to a pending row
// (the bottommost — matching the #156 idle-snap convention).
//
// Fixture discipline (insight: trollbridge job 142 I2 / global #40):
// the cursor's pre-mutation index (1, on hold B) becomes a different
// logical row after B's op moves to the resolved head. A buggy
// fix that simply "clamps to bottommost pending always" would also
// pass; the wrong-reason-passing check is that the existing
// TestApply_TickPreservesSelectionByID still passes after the fix
// (that test asserts the non-resolving by-ID path is unchanged).
func TestApplyOpsTick_CursorStaysOnPendingWhenSelectedResolves(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	// Pre-tick: three real pending ops with RequestIDs (the production
	// shape — the daemon's ops ring carries the ops, m.Holds carries
	// the matching snapshots so the URL list panel etc. has them).
	pre := []opstream.Op{
		pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		pendingOp("req-B", "B", "b.example", t0.Add(2*time.Second)),
		pendingOp("req-C", "C", "c.example", t0.Add(3*time.Second)),
	}
	m := Model{
		Ops: pre,
		Holds: []approvals.Snapshot{
			holdSnap("A", "a.example", t0.Add(1*time.Second)),
			holdSnap("B", "b.example", t0.Add(2*time.Second)),
			holdSnap("C", "c.example", t0.Add(3*time.Second)),
		},
	}
	pred := DisplayedOps(m)
	if len(pred) != 3 {
		t.Fatalf("pre-tick displayed = %d, want 3", len(pred))
	}
	for i := range pred {
		if pred[i].HoldID == "B" {
			m.Selected = i
			break
		}
	}
	if m.Selected < 0 {
		t.Fatalf("pre-tick: hold B not found in displayed list: %+v", pred)
	}

	// Ops tick: B's status flips to 200 (resolved). The daemon's
	// holds response also drops B. The op's RequestID stays "req-B"
	// — that is the anchor preserveSelection will match.
	post := []opstream.Op{
		pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		{
			RequestID: "req-B",
			Method:    "GET",
			URL:       "https://b.example/",
			Status:    "200",
			HoldID:    "", // hold released after approval
			StartedAt: t0.Add(2 * time.Second),
			UpdatedAt: t0.Add(2 * time.Second),
		},
		pendingOp("req-C", "C", "c.example", t0.Add(3*time.Second)),
	}
	m, _ = applyTick(m, TickResult{Holds: []approvals.Snapshot{
		holdSnap("A", "a.example", t0.Add(1*time.Second)),
		holdSnap("C", "c.example", t0.Add(3*time.Second)),
	}})
	m, _ = applyOpsTick(m, OpsTickResult{Ops: post})

	postd := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(postd) {
		t.Fatalf("post-tick Selected = %d out of range for %d rows", m.Selected, len(postd))
	}
	sel := postd[m.Selected]
	if opIsResolved(sel.Status) {
		t.Errorf("cursor landed on resolved row after B's op resolved; "+
			"Selected=%d (HoldID=%q ReqID=%q URL=%q status=%q); want a non-resolved (pending) row. "+
			"Full displayed list: %+v",
			m.Selected, sel.HoldID, sel.RequestID, sel.URL, sel.Status, postd)
	}
	if sel.RequestID == "req-B" {
		t.Errorf("cursor stayed on B (now resolved) instead of jumping to a remaining "+
			"pending row; Selected=%d HoldID=%q ReqID=%q status=%q",
			m.Selected, sel.HoldID, sel.RequestID, sel.Status)
	}
}

// TestApplyOpsTick_CursorStaysOnPendingUnderBurst covers the
// "even when a lot is happening" scenario from #191: in a single
// tick, the selected pending row resolves, a sibling pending row
// resolves, a new resolved op enters at the head, and new pending
// arrivals appear at the tail. The cursor must remain on a
// pending row.
func TestApplyOpsTick_CursorStaysOnPendingUnderBurst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	pre := []opstream.Op{
		pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		pendingOp("req-B", "B", "b.example", t0.Add(2*time.Second)),
		pendingOp("req-C", "C", "c.example", t0.Add(3*time.Second)),
		pendingOp("req-D", "D", "d.example", t0.Add(4*time.Second)),
	}
	m := Model{
		Ops: pre,
		Holds: []approvals.Snapshot{
			holdSnap("A", "a.example", t0.Add(1*time.Second)),
			holdSnap("B", "b.example", t0.Add(2*time.Second)),
			holdSnap("C", "c.example", t0.Add(3*time.Second)),
			holdSnap("D", "d.example", t0.Add(4*time.Second)),
		},
	}
	pred := DisplayedOps(m)
	for i := range pred {
		if pred[i].HoldID == "B" {
			m.Selected = i
			break
		}
	}
	if m.Selected < 0 {
		t.Fatalf("pre-burst setup: hold B not found in %+v", pred)
	}

	// Burst tick: B resolves (200), D resolves (denied), a fresh resolved
	// op R1 enters the ring, and two new pending holds E, F arrive.
	post := []opstream.Op{
		{
			RequestID: "req-R1",
			Method:    "GET",
			URL:       "https://r1.example/",
			Status:    "200",
			StartedAt: t0.Add(10 * time.Second),
			UpdatedAt: t0.Add(10 * time.Second),
		},
		pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		{
			RequestID: "req-B",
			Method:    "GET",
			URL:       "https://b.example/",
			Status:    "200",
			StartedAt: t0.Add(2 * time.Second),
			UpdatedAt: t0.Add(2 * time.Second),
		},
		pendingOp("req-C", "C", "c.example", t0.Add(3*time.Second)),
		{
			RequestID: "req-D",
			Method:    "GET",
			URL:       "https://d.example/",
			Status:    "denied",
			StartedAt: t0.Add(4 * time.Second),
			UpdatedAt: t0.Add(4 * time.Second),
		},
		pendingOp("req-E", "E", "e.example", t0.Add(5*time.Second)),
		pendingOp("req-F", "F", "f.example", t0.Add(6*time.Second)),
	}
	m, _ = applyTick(m, TickResult{Holds: []approvals.Snapshot{
		holdSnap("A", "a.example", t0.Add(1*time.Second)),
		holdSnap("C", "c.example", t0.Add(3*time.Second)),
		holdSnap("E", "e.example", t0.Add(5*time.Second)),
		holdSnap("F", "f.example", t0.Add(6*time.Second)),
	}})
	m, _ = applyOpsTick(m, OpsTickResult{Ops: post})

	postd := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(postd) {
		t.Fatalf("post-burst Selected = %d out of range for %d rows", m.Selected, len(postd))
	}
	sel := postd[m.Selected]
	if opIsResolved(sel.Status) {
		t.Errorf("burst: cursor landed on resolved row; Selected=%d HoldID=%q ReqID=%q URL=%q status=%q. "+
			"Full displayed list: %+v",
			m.Selected, sel.HoldID, sel.RequestID, sel.URL, sel.Status, postd)
	}
}

// TestApplyOpsTick_CursorOnResolvedStaysOnResolved guards the
// one-directional shape of the #191 section-affinity rule: the
// rule only fires when the cursor was on pending. A cursor that
// was on a resolved row before the tick must not be pulled into
// the pending region by the affinity logic. (The directive's
// invariant is "stay on pending when on pending"; there is no
// symmetric "stay on resolved" requirement, but the affinity
// must not invent one by accident.)
func TestApplyOpsTick_CursorOnResolvedStaysOnResolved(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	resolvedR1 := opstream.Op{
		RequestID: "req-R1",
		Method:    "GET",
		URL:       "https://r1.example/",
		Status:    "200",
		StartedAt: t0.Add(10 * time.Second),
		UpdatedAt: t0.Add(10 * time.Second),
	}
	m := Model{
		Ops: []opstream.Op{
			resolvedR1,
			pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		},
		Holds: []approvals.Snapshot{holdSnap("A", "a.example", t0.Add(1*time.Second))},
	}
	pred := DisplayedOps(m)
	for i := range pred {
		if pred[i].RequestID == "req-R1" {
			m.Selected = i
			break
		}
	}
	if m.Selected < 0 {
		t.Fatalf("pre-tick: req-R1 not found in %+v", pred)
	}

	// A new pending hold arrives. Cursor was on resolved-R1; it must
	// stay on R1, not get re-routed to pending.
	m, _ = applyTick(m, TickResult{Holds: []approvals.Snapshot{
		holdSnap("A", "a.example", t0.Add(1*time.Second)),
		holdSnap("B", "b.example", t0.Add(2*time.Second)),
	}})
	m, _ = applyOpsTick(m, OpsTickResult{Ops: []opstream.Op{
		resolvedR1,
		pendingOp("req-A", "A", "a.example", t0.Add(1*time.Second)),
		pendingOp("req-B", "B", "b.example", t0.Add(2*time.Second)),
	}})

	postd := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(postd) {
		t.Fatalf("post-tick Selected = %d out of range for %d rows", m.Selected, len(postd))
	}
	sel := postd[m.Selected]
	if sel.RequestID != "req-R1" {
		t.Errorf("cursor moved off resolved R1 unexpectedly; Selected=%d HoldID=%q ReqID=%q status=%q",
			m.Selected, sel.HoldID, sel.RequestID, sel.Status)
	}
}
