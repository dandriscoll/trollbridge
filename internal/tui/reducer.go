// Package tui hosts the small terminal UI for approving or denying
// held requests in real time. The reducer in this file is a pure
// function from (model, event) -> (model, command); the runtime in
// approvals.go merges three event sources (key input, refresh ticks,
// action-result callbacks) and drives the reducer.
package tui

import (
	"strings"

	"github.com/dandriscoll/drawbridge/internal/approvals"
)

// Model is the immutable state the renderer reads.
type Model struct {
	Holds    []approvals.Snapshot
	Selected int    // index into Holds, or -1 if empty.
	LastInfo string // last successful-action message shown in the footer.
	LastErr  string // last error message shown in the footer.
	Cols     int
	Rows     int
	Quit     bool
}

// Event is the input to the reducer. Concrete types are below.
type Event interface{ event() }

// TickResult arrives after a poll of /v1/holds completes.
type TickResult struct {
	Holds []approvals.Snapshot
	Err   error
}

// KeyEvent arrives when the operator presses a key.
type KeyEvent struct {
	Rune rune     // printable rune (a, d, q, j, k, etc.) or 0
	Key  KeyCode  // non-printable keys
}

// KeyCode names non-printable keys the TUI understands.
type KeyCode int

const (
	KeyNone KeyCode = iota
	KeyUp
	KeyDown
	KeyEsc
	KeyCtrlC
)

// ActionResult arrives after an approve or deny POST completes.
type ActionResult struct {
	ID     string
	Action string // "approve" | "deny"
	Err    error
}

// ResizeEvent arrives on terminal resize (SIGWINCH).
type ResizeEvent struct {
	Cols, Rows int
}

func (TickResult) event()   {}
func (KeyEvent) event()     {}
func (ActionResult) event() {}
func (ResizeEvent) event()  {}

// Cmd is the side-effect the reducer requests of the runtime.
type Cmd interface{ cmd() }

type CmdNone struct{}
type CmdRefresh struct{}
type CmdApprove struct{ ID string }
type CmdDeny struct{ ID string }
type CmdQuit struct{}

func (CmdNone) cmd()    {}
func (CmdRefresh) cmd() {}
func (CmdApprove) cmd() {}
func (CmdDeny) cmd()    {}
func (CmdQuit) cmd()    {}

// Apply is the pure reducer. It does no I/O. Callers replace their
// Model with the returned one and run the returned Cmd.
func Apply(m Model, ev Event) (Model, Cmd) {
	switch e := ev.(type) {
	case TickResult:
		return applyTick(m, e)
	case KeyEvent:
		return applyKey(m, e)
	case ActionResult:
		return applyActionResult(m, e)
	case ResizeEvent:
		m.Cols = e.Cols
		m.Rows = e.Rows
		return m, CmdNone{}
	}
	return m, CmdNone{}
}

func applyTick(m Model, e TickResult) (Model, Cmd) {
	if e.Err != nil {
		m.LastErr = "control API: " + truncate(e.Err.Error(), 200)
		return m, CmdNone{}
	}
	m.Holds = e.Holds
	m.LastErr = ""
	clampSelection(&m)
	return m, CmdNone{}
}

func applyKey(m Model, e KeyEvent) (Model, Cmd) {
	// Quit keys.
	if e.Key == KeyCtrlC || e.Key == KeyEsc || e.Rune == 'q' {
		m.Quit = true
		return m, CmdQuit{}
	}
	// Selection movement.
	if e.Key == KeyUp || e.Rune == 'k' {
		if m.Selected > 0 {
			m.Selected--
		}
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		if m.Selected < len(m.Holds)-1 {
			m.Selected++
		}
		return m, CmdNone{}
	}
	// Refresh now.
	if e.Rune == 'r' {
		return m, CmdRefresh{}
	}
	// Approve / deny on the highlighted hold.
	if e.Rune == 'a' || e.Rune == 'd' {
		if m.Selected < 0 || m.Selected >= len(m.Holds) {
			m.LastErr = "no hold selected"
			return m, CmdNone{}
		}
		id := m.Holds[m.Selected].ID
		if e.Rune == 'a' {
			m.LastInfo = "approving " + id + "…"
			return m, CmdApprove{ID: id}
		}
		m.LastInfo = "denying " + id + "…"
		return m, CmdDeny{ID: id}
	}
	return m, CmdNone{}
}

func applyActionResult(m Model, e ActionResult) (Model, Cmd) {
	if e.Err != nil {
		m.LastErr = e.Action + " " + e.ID + ": " + truncate(e.Err.Error(), 200)
		m.LastInfo = ""
		return m, CmdNone{}
	}
	// Optimistically remove the resolved hold; the next tick
	// re-fetches the authoritative list anyway.
	m.Holds = removeHold(m.Holds, e.ID)
	m.LastInfo = e.Action + "d " + e.ID
	m.LastErr = ""
	clampSelection(&m)
	// Refresh immediately so the operator sees the authoritative
	// list update without waiting a full tick.
	return m, CmdRefresh{}
}

func removeHold(holds []approvals.Snapshot, id string) []approvals.Snapshot {
	out := holds[:0:0]
	for _, h := range holds {
		if h.ID != id {
			out = append(out, h)
		}
	}
	return out
}

func clampSelection(m *Model) {
	if len(m.Holds) == 0 {
		m.Selected = -1
		return
	}
	if m.Selected < 0 {
		m.Selected = 0
	}
	if m.Selected >= len(m.Holds) {
		m.Selected = len(m.Holds) - 1
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimRight(s[:n], " ") + "…"
}
