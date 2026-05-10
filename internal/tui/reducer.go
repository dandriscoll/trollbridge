// Package tui hosts the unified two-pane operator UI: an approvals
// pane (top) listing pending holds, and a console pane (bottom) for
// allow/deny/list/remove/reload/test/doctor/help/quit commands. The
// reducer in this file is a pure function from (model, event) to
// (model, command); the runtime in approvals.go merges three event
// sources (key input, refresh ticks, action-result callbacks) and
// drives the reducer.
package tui

import (
	"strings"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// Pane names a top-level focusable surface.
type Pane int

const (
	PaneApprovals Pane = iota
	PaneConsole
)

// ConsoleModel is the lower-pane state: a scrollback buffer plus the
// current input line and cursor.
type ConsoleModel struct {
	Scrollback []string // newest at the end; capped at maxScrollback
	Input      []rune   // current input line
	Cursor     int      // rune index in Input where the next char lands
	Prompt     string   // render prefix; defaults to "trollbridge> "
}

const maxScrollback = 200

// Model is the immutable state the renderer reads.
type Model struct {
	// Ops drives the upper-pane render: a unified rolling list of
	// recent operations, with pending-approval entries distinguished
	// by Status == opstream.StatusPending. Selection indexes into
	// this slice (closes #52).
	Ops []opstream.Op
	// Holds is the authoritative list of currently-pending approvals.
	// Kept alongside Ops because (a) the CLI surfaces still need a
	// holds view and (b) holds that have been evicted from the ops
	// ring under burst pressure are merged back into the displayed
	// list so the operator never silently loses an actionable hold.
	Holds    []approvals.Snapshot
	Selected int    // index into displayed-ops list, or -1 if empty.
	LastInfo string // last successful-action message shown in the upper-pane footer.
	LastErr  string // last error message shown in the upper-pane footer.
	Cols     int
	Rows     int
	Quit     bool

	Focused Pane
	Console ConsoleModel
}

// Event is the input to the reducer. Concrete types are below.
type Event interface{ event() }

// TickResult arrives after a poll of /v1/holds completes.
type TickResult struct {
	Holds []approvals.Snapshot
	Err   error
}

// OpsTickResult arrives after a poll of /v1/ops completes.
type OpsTickResult struct {
	Ops []opstream.Op
	Err error
}

// KeyEvent arrives when the operator presses a key.
type KeyEvent struct {
	Rune rune    // printable rune (a, d, q, j, k, etc.) or 0
	Key  KeyCode // non-printable keys
}

// KeyCode names non-printable keys the TUI understands.
type KeyCode int

const (
	KeyNone KeyCode = iota
	KeyUp
	KeyDown
	KeyEsc
	KeyCtrlC
	KeyTab
	KeyEnter
	KeyBackspace
	KeyCtrlU
)

// ActionResult arrives after an approve or deny POST completes.
type ActionResult struct {
	ID     string
	Action string // "approve" | "deny"
	Err    error
}

// ConsoleExecResult arrives after the runtime executed a console
// command line. Output already carries any trailing newlines the
// backend wrote; the reducer appends it to the scrollback.
type ConsoleExecResult struct {
	Line   string
	Output string
	Quit   bool
}

// ResizeEvent arrives on terminal resize (SIGWINCH).
type ResizeEvent struct {
	Cols, Rows int
}

func (TickResult) event()        {}
func (OpsTickResult) event()     {}
func (KeyEvent) event()          {}
func (ActionResult) event()      {}
func (ResizeEvent) event()       {}
func (ConsoleExecResult) event() {}

// Cmd is the side-effect the reducer requests of the runtime.
type Cmd interface{ cmd() }

type CmdNone struct{}
type CmdRefresh struct{}
type CmdApprove struct{ ID string }
type CmdDeny struct{ ID string }
type CmdQuit struct{}
type CmdConsoleExec struct{ Line string }

func (CmdNone) cmd()        {}
func (CmdRefresh) cmd()     {}
func (CmdApprove) cmd()     {}
func (CmdDeny) cmd()        {}
func (CmdQuit) cmd()        {}
func (CmdConsoleExec) cmd() {}

// Apply is the pure reducer. It does no I/O. Callers replace their
// Model with the returned one and run the returned Cmd.
func Apply(m Model, ev Event) (Model, Cmd) {
	switch e := ev.(type) {
	case TickResult:
		return applyTick(m, e)
	case OpsTickResult:
		return applyOpsTick(m, e)
	case KeyEvent:
		return applyKey(m, e)
	case ActionResult:
		return applyActionResult(m, e)
	case ConsoleExecResult:
		return applyConsoleExec(m, e)
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
	preserveSelectionByRequestID(&m)
	clampSelection(&m)
	return m, CmdNone{}
}

func applyOpsTick(m Model, e OpsTickResult) (Model, Cmd) {
	if e.Err != nil {
		m.LastErr = "control API (ops): " + truncate(e.Err.Error(), 200)
		return m, CmdNone{}
	}
	m.Ops = e.Ops
	m.LastErr = ""
	preserveSelectionByRequestID(&m)
	clampSelection(&m)
	return m, CmdNone{}
}

// preserveSelectionByRequestID keeps the operator's selection on the
// same logical operation across refresh ticks (closes #39 and the
// per-tick rebinding of #52). When the displayed list rebuilds, the
// previously-selected row's request_id (or hold_id, for holds-only
// rows) is re-located in the new list.
func preserveSelectionByRequestID(m *Model) {
	displayed := DisplayedOps(*m)
	prevKey := ""
	if m.Selected >= 0 && m.Selected < len(displayed) {
		prevKey = displayed[m.Selected].RequestID
		if prevKey == "" {
			prevKey = "hold:" + displayed[m.Selected].HoldID
		}
	}
	if prevKey == "" {
		return
	}
	rebuilt := DisplayedOps(*m)
	m.Selected = -1
	for i, o := range rebuilt {
		key := o.RequestID
		if key == "" {
			key = "hold:" + o.HoldID
		}
		if key == prevKey {
			m.Selected = i
			return
		}
	}
}

func applyKey(m Model, e KeyEvent) (Model, Cmd) {
	// Global keys — fire regardless of focus.
	if e.Key == KeyCtrlC {
		m.Quit = true
		return m, CmdQuit{}
	}
	if e.Key == KeyTab {
		if m.Focused == PaneApprovals {
			m.Focused = PaneConsole
		} else {
			m.Focused = PaneApprovals
		}
		return m, CmdNone{}
	}
	// Pane-specific dispatch.
	if m.Focused == PaneConsole {
		return applyKeyConsole(m, e)
	}
	return applyKeyApprovals(m, e)
}

func applyKeyApprovals(m Model, e KeyEvent) (Model, Cmd) {
	if e.Key == KeyEsc || e.Rune == 'q' {
		m.Quit = true
		return m, CmdQuit{}
	}
	displayed := DisplayedOps(m)
	if e.Key == KeyUp || e.Rune == 'k' {
		if m.Selected > 0 {
			m.Selected--
		}
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		if m.Selected < len(displayed)-1 {
			m.Selected++
		}
		return m, CmdNone{}
	}
	if e.Rune == 'r' {
		return m, CmdRefresh{}
	}
	if e.Rune == 'a' || e.Rune == 'd' {
		if m.Selected < 0 || m.Selected >= len(displayed) {
			m.LastErr = "no operation selected"
			return m, CmdNone{}
		}
		op := displayed[m.Selected]
		if op.HoldID == "" || op.Status != opstream.StatusPending {
			m.LastErr = "selected operation is not pending approval"
			return m, CmdNone{}
		}
		if e.Rune == 'a' {
			m.LastInfo = "approving " + op.HoldID + "…"
			return m, CmdApprove{ID: op.HoldID}
		}
		m.LastInfo = "denying " + op.HoldID + "…"
		return m, CmdDeny{ID: op.HoldID}
	}
	return m, CmdNone{}
}

func applyKeyConsole(m Model, e KeyEvent) (Model, Cmd) {
	switch e.Key {
	case KeyEnter:
		line := string(m.Console.Input)
		m.Console.Input = nil
		m.Console.Cursor = 0
		// Echo the prompt + input as the first scrollback entry of
		// the round; the runtime then appends the backend output.
		m.Console = appendScrollback(m.Console, m.Console.Prompt+line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return m, CmdNone{}
		}
		return m, CmdConsoleExec{Line: trimmed}
	case KeyBackspace:
		if m.Console.Cursor > 0 {
			m.Console.Input = append(m.Console.Input[:m.Console.Cursor-1], m.Console.Input[m.Console.Cursor:]...)
			m.Console.Cursor--
		}
		return m, CmdNone{}
	case KeyCtrlU:
		m.Console.Input = nil
		m.Console.Cursor = 0
		return m, CmdNone{}
	case KeyEsc:
		// Esc inside the console pane returns focus to approvals
		// rather than quitting the UI — operators expect Esc to
		// "back out" of the input mode.
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	if e.Rune != 0 {
		m.Console.Input = append(m.Console.Input[:m.Console.Cursor:m.Console.Cursor], append([]rune{e.Rune}, m.Console.Input[m.Console.Cursor:]...)...)
		m.Console.Cursor++
	}
	return m, CmdNone{}
}

func applyActionResult(m Model, e ActionResult) (Model, Cmd) {
	if e.Err != nil {
		m.LastErr = e.Action + " " + e.ID + ": " + truncate(e.Err.Error(), 200)
		m.LastInfo = ""
		return m, CmdNone{}
	}
	// Optimistically remove the resolved hold; the next tick re-
	// fetches the authoritative list anyway. The corresponding ops
	// entry will transition to its terminal status on the next ops
	// tick when writeAudit fires.
	m.Holds = removeHold(m.Holds, e.ID)
	m.LastInfo = e.Action + "d " + e.ID
	m.LastErr = ""
	clampSelection(&m)
	return m, CmdRefresh{}
}

func applyConsoleExec(m Model, e ConsoleExecResult) (Model, Cmd) {
	for _, line := range splitLines(e.Output) {
		m.Console = appendScrollback(m.Console, line)
	}
	if e.Quit {
		m.Quit = true
		return m, CmdQuit{}
	}
	return m, CmdNone{}
}

func appendScrollback(c ConsoleModel, line string) ConsoleModel {
	c.Scrollback = append(c.Scrollback, line)
	if len(c.Scrollback) > maxScrollback {
		c.Scrollback = c.Scrollback[len(c.Scrollback)-maxScrollback:]
	}
	return c
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimRight(s, "\n")
	return strings.Split(s, "\n")
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
	displayed := DisplayedOps(*m)
	if len(displayed) == 0 {
		m.Selected = -1
		return
	}
	if m.Selected < 0 {
		m.Selected = 0
	}
	if m.Selected >= len(displayed) {
		m.Selected = len(displayed) - 1
	}
}

// DisplayedOps returns the unified list rendered in the upper pane:
// the ops ring (newest first) merged with any pending holds that the
// ring no longer carries (evicted under burst pressure). Holds that
// are NOT in the ring become synthetic ops with status "pending" so
// the operator never silently loses an actionable hold.
func DisplayedOps(m Model) []opstream.Op {
	out := append([]opstream.Op(nil), m.Ops...)
	seenHoldIDs := map[string]struct{}{}
	for _, o := range out {
		if o.HoldID != "" {
			seenHoldIDs[o.HoldID] = struct{}{}
		}
	}
	for _, h := range m.Holds {
		if _, ok := seenHoldIDs[h.ID]; ok {
			continue
		}
		// Synthetic op for an unknown-to-ring hold. RequestID is empty
		// (ring eviction lost it) so selection-preservation falls back
		// to the hold:<id> key path.
		url := h.Host
		if h.Port > 0 {
			url = h.Host + ":" + itoaPort(h.Port)
		}
		if h.Path != "" && h.Scheme != "" {
			url = h.Scheme + "://" + url + h.Path
		}
		out = append(out, opstream.Op{
			Method:    h.Method,
			URL:       url,
			Status:    opstream.StatusPending,
			HoldID:    h.ID,
			StartedAt: h.CreatedAt,
			UpdatedAt: h.CreatedAt,
		})
	}
	return out
}

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimRight(s[:n], " ") + "…"
}
