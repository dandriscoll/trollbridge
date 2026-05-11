package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestAlerts_ChimeFiresOnRisingPending pins the wire contract for
// #72: the reducer emits CmdRingBell exactly when the pending count
// rises AND the chime is enabled.
func TestAlerts_ChimeFiresOnRisingPending(t *testing.T) {
	m := Model{
		Cols: 80, Rows: 24,
		Alerts: AlertsState{ChimeEnabled: true},
	}
	ev := OpsTickResult{Ops: []opstream.Op{
		{RequestID: "r1", URL: "u", Status: opstream.StatusPending},
	}}
	got, cmd := Apply(m, ev)
	if _, ok := cmd.(CmdRingBell); !ok {
		t.Errorf("first pending op: cmd = %T, want CmdRingBell", cmd)
	}
	if got.Alerts.LastPendingSeen != 1 {
		t.Errorf("LastPendingSeen = %d, want 1", got.Alerts.LastPendingSeen)
	}
}

func TestAlerts_ChimeSilentOnSamePending(t *testing.T) {
	m := Model{
		Cols: 80, Rows: 24,
		Alerts: AlertsState{ChimeEnabled: true, LastPendingSeen: 1},
		Ops: []opstream.Op{
			{RequestID: "r1", URL: "u", Status: opstream.StatusPending},
		},
	}
	ev := OpsTickResult{Ops: []opstream.Op{
		{RequestID: "r1", URL: "u", Status: opstream.StatusPending},
	}}
	_, cmd := Apply(m, ev)
	if _, ok := cmd.(CmdRingBell); ok {
		t.Errorf("steady-state pending: cmd = CmdRingBell, want CmdNone — the chime must not re-fire on every tick")
	}
}

func TestAlerts_ChimeSilentOnFallingPending(t *testing.T) {
	m := Model{
		Cols: 80, Rows: 24,
		Alerts: AlertsState{ChimeEnabled: true, LastPendingSeen: 2},
	}
	ev := OpsTickResult{Ops: []opstream.Op{
		{RequestID: "r1", URL: "u", Status: opstream.StatusPending},
	}}
	got, cmd := Apply(m, ev)
	if _, ok := cmd.(CmdRingBell); ok {
		t.Errorf("pending dropping: cmd = CmdRingBell, want CmdNone — only rises should chime")
	}
	if got.Alerts.LastPendingSeen != 1 {
		t.Errorf("LastPendingSeen = %d, want 1 (must track current count even on drops)", got.Alerts.LastPendingSeen)
	}
}

func TestAlerts_ChimeSilentWhenDisabled(t *testing.T) {
	m := Model{
		Cols: 80, Rows: 24,
		Alerts: AlertsState{ChimeEnabled: false},
	}
	ev := OpsTickResult{Ops: []opstream.Op{
		{RequestID: "r1", URL: "u", Status: opstream.StatusPending},
	}}
	got, cmd := Apply(m, ev)
	if _, ok := cmd.(CmdRingBell); ok {
		t.Errorf("chime disabled: cmd = CmdRingBell, want CmdNone")
	}
	// LastPendingSeen must still advance — otherwise re-enabling the
	// chime mid-session would replay an outdated baseline.
	if got.Alerts.LastPendingSeen != 1 {
		t.Errorf("LastPendingSeen = %d, want 1 (state must advance even when muted)", got.Alerts.LastPendingSeen)
	}
}

func TestAlerts_BellKeyTogglesChime(t *testing.T) {
	m := Model{
		Cols: 80, Rows: 24, Focused: PaneApprovals,
		Alerts: AlertsState{ChimeEnabled: true},
	}
	got, _ := Apply(m, KeyEvent{Rune: 'b'})
	if got.Alerts.ChimeEnabled {
		t.Errorf("after 'b' from on: ChimeEnabled = true, want false")
	}
	if !strings.Contains(got.LastInfo, "muted") {
		t.Errorf("LastInfo missing 'muted' hint: %q", got.LastInfo)
	}
	got2, _ := Apply(got, KeyEvent{Rune: 'b'})
	if !got2.Alerts.ChimeEnabled {
		t.Errorf("after second 'b': ChimeEnabled = false, want true")
	}
	if !strings.Contains(got2.LastInfo, "on") {
		t.Errorf("LastInfo missing 'on' hint after unmute: %q", got2.LastInfo)
	}
}

// TestAlerts_PaneLabelCarriesVisualIndicatorWhenPending pins that
// the rendered approvals-pane label gains a bell glyph + bold-red
// ANSI wrap around the pending count when pending > 0. Closes the
// #72 "very distinct visual indication" requirement.
func TestAlerts_PaneLabelCarriesVisualIndicatorWhenPending(t *testing.T) {
	withPending := formatOpsPaneLabelText(5, 2)
	if !strings.Contains(withPending, "\x1b[1;31m") {
		t.Errorf("label missing bold-red ANSI escape when pending>0: %q", withPending)
	}
	if !strings.Contains(withPending, "␇") {
		t.Errorf("label missing bell glyph when pending>0: %q", withPending)
	}
	if !strings.Contains(withPending, "2 pending") {
		t.Errorf("label does not name the count: %q", withPending)
	}

	noPending := formatOpsPaneLabelText(5, 0)
	if strings.Contains(noPending, "\x1b[1;31m") {
		t.Errorf("label carries bold-red ANSI when pending=0: %q", noPending)
	}
	if strings.Contains(noPending, "␇") {
		t.Errorf("label carries bell glyph when pending=0: %q", noPending)
	}
}

func TestAlerts_DefaultOptionsChimeOn(t *testing.T) {
	opts := DefaultOptions()
	if !opts.ChimeEnabled {
		t.Error("DefaultOptions: ChimeEnabled = false, want true (operators opt OUT, not in)")
	}
}