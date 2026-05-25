package tui

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyAction_ApproveHoldGoneFallsBackToAllow pins #184: when an
// approve fails because the hold was already resolved out from under
// the operator, the action falls back to writing the URL to the allow
// list (the #60 retroactive-add path) instead of dead-ending on
// "hold not found".
func TestApplyAction_ApproveHoldGoneFallsBackToAllow(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	err := fmt.Errorf("%w: hold-x", controlclient.ErrHoldNotFound)
	got, cmd := Apply(m, ActionResult{
		ID: "hold-x", Action: "approve", Method: "GET",
		URL: "https://api.example.com/v1", Err: err,
	})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec fallback", cmd)
	}
	if exec.Line != "allow GET https://api.example.com/v1" {
		t.Errorf("Line = %q, want %q", exec.Line, "allow GET https://api.example.com/v1")
	}
	if got.LastErr != "" {
		t.Errorf("LastErr = %q, want empty (error suppressed by fallback)", got.LastErr)
	}
	if got.LastInfo == "" {
		t.Errorf("LastInfo empty, want a status line for the fallback")
	}
}

// TestApplyAction_DenyHoldGoneFallsBackToDeny — symmetric sibling.
func TestApplyAction_DenyHoldGoneFallsBackToDeny(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	err := fmt.Errorf("%w: hold-y", controlclient.ErrHoldNotFound)
	_, cmd := Apply(m, ActionResult{
		ID: "hold-y", Action: "deny", Method: "POST",
		URL: "evil.example.com", Err: err,
	})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec fallback", cmd)
	}
	if exec.Line != "deny POST evil.example.com" {
		t.Errorf("Line = %q, want %q", exec.Line, "deny POST evil.example.com")
	}
}

// TestApplyAction_NonHoldNotFoundStillErrors pins that the fallback is
// scoped to the hold-not-found class only — a transport/other error
// must still surface to the operator, not silently allow the URL.
func TestApplyAction_NonHoldNotFoundStillErrors(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	_, cmd := Apply(m, ActionResult{
		ID: "hold-z", Action: "approve", Method: "GET",
		URL: "https://x/", Err: errors.New("control API: connection refused"),
	})
	if _, ok := cmd.(CmdConsoleExec); ok {
		t.Fatalf("a non-hold-not-found error must NOT fall back to an allow write")
	}
	got, _ := Apply(m, ActionResult{
		ID: "hold-z", Action: "approve", Method: "GET",
		URL: "https://x/", Err: errors.New("control API: connection refused"),
	})
	if got.LastErr == "" {
		t.Errorf("LastErr empty, want the transport error surfaced")
	}
}

// TestApplyAction_HoldGoneNoURLDoesNotAllow pins that without a URL we
// cannot fabricate an allow pattern, so we must not emit a console
// exec — the empty-pattern case degrades to the normal error path.
func TestApplyAction_HoldGoneNoURLDoesNotAllow(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	err := fmt.Errorf("%w: hold-x", controlclient.ErrHoldNotFound)
	_, cmd := Apply(m, ActionResult{ID: "hold-x", Action: "approve", Err: err})
	if _, ok := cmd.(CmdConsoleExec); ok {
		t.Fatalf("with no URL there is nothing to allow; must not emit CmdConsoleExec")
	}
}

// TestApprove_EmitsMethodAndURL pins that pressing 'a' on a pending row
// captures the row's Method and URL on the command, so the action-
// result handler has the pattern for the #184 fallback even if the row
// later rotates out of the ring.
func TestApprove_EmitsMethodAndURL(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "POST", URL: "https://x/y", Status: opstream.StatusPending, HoldID: "hold-1"},
		},
		Selected: 0,
	}
	_, cmd := Apply(m, KeyEvent{Rune: 'a'})
	approve, ok := cmd.(CmdApprove)
	if !ok {
		t.Fatalf("cmd = %T, want CmdApprove", cmd)
	}
	if approve.Method != "POST" || approve.URL != "https://x/y" {
		t.Errorf("CmdApprove Method/URL = %q/%q, want POST/https://x/y", approve.Method, approve.URL)
	}
}

// TestInProcessClient_ApproveMissingHoldIsSentinel pins that the
// in-process client wraps a missing-hold failure in the shared
// ErrHoldNotFound sentinel, so the reducer can detect the class (the
// HTTP client already does this).
func TestInProcessClient_ApproveMissingHoldIsSentinel(t *testing.T) {
	c := &inProcessClient{q: approvals.New(10, time.Minute, "deny")}
	if err := c.Approve("nope"); !errors.Is(err, controlclient.ErrHoldNotFound) {
		t.Errorf("Approve(missing) err = %v, want errors.Is ErrHoldNotFound", err)
	}
	if err := c.Deny("nope", "x"); !errors.Is(err, controlclient.ErrHoldNotFound) {
		t.Errorf("Deny(missing) err = %v, want errors.Is ErrHoldNotFound", err)
	}
}
