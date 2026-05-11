package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyKey_RetroactiveAllowOnCompletedRow pins #60: pressing 'a'
// on a non-pending row routes through the console pane as
// `allow <url>` rather than firing a CmdApprove against a non-existent
// hold.
func TestApplyKey_RetroactiveAllowOnCompletedRow(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "https://api.example.com/v1", Status: "200"},
		},
		Selected: 0,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec for retroactive add", cmd)
	}
	if exec.Line != "allow https://api.example.com/v1" {
		t.Errorf("CmdConsoleExec.Line = %q, want %q", exec.Line, "allow https://api.example.com/v1")
	}
	if !strings.Contains(got.LastInfo, "allow") {
		t.Errorf("LastInfo = %q, want it to mention allow", got.LastInfo)
	}
}

// TestApplyKey_RetroactiveDenyOnCompletedRow — symmetric for 'd'.
func TestApplyKey_RetroactiveDenyOnCompletedRow(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "evil.example.com", Status: "470"},
		},
		Selected: 0,
	}
	_, cmd := Apply(m, KeyEvent{Rune: 'd'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	if exec.Line != "deny evil.example.com" {
		t.Errorf("Line = %q, want %q", exec.Line, "deny evil.example.com")
	}
}

// TestApplyKey_PendingRowStillFiresApprove pins that the existing
// pending-hold path is preserved.
func TestApplyKey_PendingRowStillFiresApprove(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "POST", URL: "https://x/", Status: opstream.StatusPending, HoldID: "hold-1"},
		},
		Selected: 0,
	}
	_, cmd := Apply(m, KeyEvent{Rune: 'a'})
	approve, ok := cmd.(CmdApprove)
	if !ok {
		t.Fatalf("cmd = %T, want CmdApprove (pending path preserved)", cmd)
	}
	if approve.ID != "hold-1" {
		t.Errorf("CmdApprove.ID = %q, want %q", approve.ID, "hold-1")
	}
}
