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
	Holds    []approvals.Snapshot
	Selected int    // index into Holds, or -1 if empty.
	LastInfo string // last successful-action message shown in the approvals footer.
	LastErr  string // last error message shown in the approvals footer.
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
	// Preserve the operator's selection across reorders by tracking
	// the previously-selected hold's ID into the new list (closes #39).
	// If the prior hold has resolved, fall through to clampSelection
	// which picks a sane index.
	prevID := ""
	if m.Selected >= 0 && m.Selected < len(m.Holds) {
		prevID = m.Holds[m.Selected].ID
	}
	m.Holds = e.Holds
	m.LastErr = ""
	if prevID != "" {
		m.Selected = -1
		for i, h := range m.Holds {
			if h.ID == prevID {
				m.Selected = i
				break
			}
		}
	}
	clampSelection(&m)
	return m, CmdNone{}
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
	if e.Rune == 'r' {
		return m, CmdRefresh{}
	}
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
	// fetches the authoritative list anyway.
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
