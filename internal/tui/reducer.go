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

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// Pane names a top-level focusable surface.
type Pane int

const (
	PaneApprovals Pane = iota
	PaneConsole
)

// BottomPanel names which content the lower half of the screen shows
// when the bottom pane is open. The default Model has Open=false so
// only the approvals pane is rendered; the operator opens a panel via
// 1/2/3/4 and closes any open panel with 0. Selection is independent
// of visibility so re-pressing the same number is idempotent and the
// last-used selection survives a hide/show cycle (closes #66).
type BottomPanel int

const (
	BottomPanelConsole BottomPanel = iota
	BottomPanelInfo
	BottomPanelLLM
	BottomPanelURLs
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

	// BottomPanel selects which content the lower half shows when
	// BottomPanelOpen is true. BottomPanel always holds a valid
	// selection so re-opening the same panel is idempotent (closes
	// #66).
	BottomPanel BottomPanel
	// BottomPanelOpen decides whether the bottom pane is visible at
	// all. Zero value (false) is the default: the approvals pane fills
	// the screen and the operator opts in to a bottom panel via the
	// 1/2/3/4 hotkeys (closes #66, reactivation).
	BottomPanelOpen bool
	// Digests is the rolling advisor-classify log shown by the LLM
	// bottom panel. Filled by DigestTickResult events.
	Digests []advisor.Digest

	// Alerts carries the operator-attention state (chime on new
	// pending; visual indicator is always-on in the renderer). The
	// chime can be muted at runtime with `b` or pre-muted in config
	// via `tui.alerts.chime: false`. Closes #72.
	Alerts AlertsState
}

// AlertsState carries the chime toggle plus the last pending count
// observed by the reducer (so the chime fires only on transitions
// UP, not on every tick that has pending requests).
type AlertsState struct {
	ChimeEnabled    bool
	LastPendingSeen int
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

// DigestTickResult arrives after a poll for recent LLM digests
// completes. Used to back the LLM bottom panel (closes #66).
type DigestTickResult struct {
	Digests []advisor.Digest
	Err     error
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
func (DigestTickResult) event()  {}
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

// CmdRingBell is emitted on the tick where the pending count
// transitions up (e.g. 0→1 or 2→3) and the chime is enabled. The
// runtime writes a single BEL byte to the TUI output stream;
// terminal emulators then beep / flash per their own settings.
type CmdRingBell struct{}
type CmdQuit struct{}
type CmdConsoleExec struct{ Line string }
type CmdDigestRefresh struct{}

func (CmdNone) cmd()          {}
func (CmdRefresh) cmd()       {}
func (CmdApprove) cmd()       {}
func (CmdDeny) cmd()          {}
func (CmdQuit) cmd()          {}
func (CmdConsoleExec) cmd()   {}
func (CmdDigestRefresh) cmd() {}
func (CmdRingBell) cmd()      {}

// Apply is the pure reducer. It does no I/O. Callers replace their
// Model with the returned one and run the returned Cmd.
func Apply(m Model, ev Event) (Model, Cmd) {
	switch e := ev.(type) {
	case TickResult:
		return applyTick(m, e)
	case OpsTickResult:
		return applyOpsTick(m, e)
	case DigestTickResult:
		if e.Err == nil {
			m.Digests = e.Digests
		}
		return m, CmdNone{}
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

	// Pending-rose detection. PendingCount surveys the same
	// displayed-ops list the renderer's label uses, so the chime is
	// in lockstep with what the operator visually counts. Fire only
	// on transitions UP — a drop to zero (operator cleared the queue)
	// is silent. (#72)
	curr := PendingCount(m)
	prev := m.Alerts.LastPendingSeen
	m.Alerts.LastPendingSeen = curr
	if curr > prev && m.Alerts.ChimeEnabled {
		return m, CmdRingBell{}
	}
	return m, CmdNone{}
}

// PendingCount returns the number of displayed ops currently in the
// pending-approval state. Exposed for use by the renderer (so the
// label, the chime detection, and any tests are computed from a
// single source) and by tests asserting the alert contract.
func PendingCount(m Model) int {
	n := 0
	for _, o := range DisplayedOps(m) {
		if o.Status == opstream.StatusPending {
			n++
		}
	}
	return n
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
		// Tab cycles focus to the bottom pane only when something is
		// down there to focus on. Pre-#66-reactivation, Tab toggled
		// unconditionally; the new default has no bottom pane to focus
		// when BottomPanelOpen is false, so Tab is a no-op then.
		if !m.BottomPanelOpen {
			return m, CmdNone{}
		}
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
	// Bottom-panel switcher (closes #66). Numbered keys 1/2/3/4 open
	// or switch panels; 0 closes any open panel back to
	// approvals-only. Pressing a digit whose panel is already
	// visible toggles it closed — same result as 0 from that state
	// (closes #76). The approvals key set already consumes
	// a/d/j/k/r/q/Tab so the numeric row was free; '0' is the
	// natural "nothing selected" member of that row.
	switch e.Rune {
	case '0':
		m.BottomPanelOpen = false
		// If the operator had Tabbed into the bottom pane before
		// hiding it, snap focus back to approvals — there is no
		// visible pane to keep focus on.
		m.Focused = PaneApprovals
		return m, CmdNone{}
	case '1':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelConsole {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelConsole
		m.BottomPanelOpen = true
		// Auto-focus the console panel so the operator can begin
		// typing without an explicit Tab press (closes #77). Info /
		// LLM panels are read-only displays and keep approvals focus
		// so single-keystroke actions (q, 0) still work; URLs panel
		// will join this auto-focus set when #79 makes it editable.
		m.Focused = PaneConsole
		return m, CmdNone{}
	case '2':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelInfo {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelInfo
		m.BottomPanelOpen = true
		return m, CmdNone{}
	case '3':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelLLM {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelLLM
		m.BottomPanelOpen = true
		return m, CmdDigestRefresh{}
	case '4':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelURLs {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelURLs
		m.BottomPanelOpen = true
		return m, CmdNone{}
	}
	if e.Rune == 'b' {
		m.Alerts.ChimeEnabled = !m.Alerts.ChimeEnabled
		if m.Alerts.ChimeEnabled {
			m.LastInfo = "chime: on (press 'b' to mute)"
		} else {
			m.LastInfo = "chime: muted (press 'b' to unmute)"
		}
		return m, CmdNone{}
	}
	if e.Rune == 'a' || e.Rune == 'd' {
		if m.Selected < 0 || m.Selected >= len(displayed) {
			m.LastErr = "no operation selected"
			return m, CmdNone{}
		}
		op := displayed[m.Selected]
		if op.HoldID != "" && op.Status == opstream.StatusPending {
			if e.Rune == 'a' {
				m.LastInfo = "approving " + op.HoldID + "…"
				return m, CmdApprove{ID: op.HoldID}
			}
			m.LastInfo = "denying " + op.HoldID + "…"
			return m, CmdDeny{ID: op.HoldID}
		}
		// Retroactive add to allow / deny list (closes #60). Routed
		// through the console pane so the same configwrite + oplog
		// shape runs as if the operator had typed `allow <url>`.
		if op.URL == "" {
			m.LastErr = "selected row has no URL to add"
			return m, CmdNone{}
		}
		verb := "allow"
		if e.Rune == 'd' {
			verb = "deny"
		}
		m.LastInfo = verb + "ing " + op.URL + "…"
		return m, CmdConsoleExec{Line: verb + " " + op.URL}
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

// DisplayedOp wraps an opstream.Op with a Count of how many
// individual requests collapsed into this row at display time
// (closes #63). The underlying Op is embedded, so callers continue
// to read .RequestID / .HoldID / .Status / .URL etc. directly.
type DisplayedOp struct {
	opstream.Op
	Count int
}

// DisplayedOps returns the unified list rendered in the upper pane:
// the ops ring (newest first) merged with any pending holds that the
// ring no longer carries (evicted under burst pressure). Holds that
// are NOT in the ring become synthetic ops with status "pending" so
// the operator never silently loses an actionable hold.
//
// Ops are then grouped by (Method, URL); each group's representative
// is the newest op (first in the newest-first ordering) and Count
// records the underlying repetition (closes #63).
func DisplayedOps(m Model) []DisplayedOp {
	flat := append([]opstream.Op(nil), m.Ops...)
	seenHoldIDs := map[string]struct{}{}
	for _, o := range flat {
		if o.HoldID != "" {
			seenHoldIDs[o.HoldID] = struct{}{}
		}
	}
	for _, h := range m.Holds {
		if _, ok := seenHoldIDs[h.ID]; ok {
			continue
		}
		url := h.Host
		if h.Port > 0 {
			url = h.Host + ":" + itoaPort(h.Port)
		}
		if h.Path != "" && h.Scheme != "" {
			url = h.Scheme + "://" + url + h.Path
		}
		flat = append(flat, opstream.Op{
			Method:    h.Method,
			URL:       url,
			Status:    opstream.StatusPending,
			HoldID:    h.ID,
			StartedAt: h.CreatedAt,
			UpdatedAt: h.CreatedAt,
		})
	}

	type key struct{ method, url string }
	indexOf := map[key]int{}
	out := make([]DisplayedOp, 0, len(flat))
	for _, o := range flat {
		k := key{o.Method, o.URL}
		if i, ok := indexOf[k]; ok {
			out[i].Count++
			// Most-recent representative wins.
			if o.UpdatedAt.After(out[i].UpdatedAt) {
				cnt := out[i].Count
				out[i].Op = o
				out[i].Count = cnt
			}
			continue
		}
		indexOf[k] = len(out)
		out = append(out, DisplayedOp{Op: o, Count: 1})
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
