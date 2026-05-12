// Package tui hosts the unified two-pane operator UI: an approvals
// pane (top) listing pending holds, and a console pane (bottom) for
// allow/deny/list/remove/reload/test/doctor/help/quit commands. The
// reducer in this file is a pure function from (model, event) to
// (model, command); the runtime in approvals.go merges three event
// sources (key input, refresh ticks, action-result callbacks) and
// drives the reducer.
package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
)

var _ = opstream.Op{}

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
	// DigestSelected is the RequestID of the digest currently
	// highlighted in the LLM bottom panel. Empty string means no
	// selection (panel empty or never focused). Tracked by stable
	// RequestID — not by slice index — so the selection survives
	// DigestTickResult re-orderings and ring evictions (insight 12).
	DigestSelected string
	// DigestExpanded is true when the operator has pressed Enter on
	// the selected digest to reveal its full detail. The renderer
	// decides inline-vs-modal layout at draw time based on whether
	// the detail block fits in the panel's available rows (closes
	// #81).
	DigestExpanded bool

	// Alerts carries the operator-attention state (chime on new
	// pending; visual indicator is always-on in the renderer). The
	// chime can be muted at runtime with `b` or pre-muted in config
	// via `tui.alerts.chime: false`. Closes #72.
	Alerts AlertsState

	// AllowList / DenyList back the URLs bottom panel — which, per
	// #79, is the operator's view of `lists.allow` / `lists.deny`
	// from trollbridge.yaml, not a roll-up of ops-ring URLs.
	// Refreshed by URLsTickResult after a CmdURLsRefresh. URLsLocal
	// is true when the runtime has a config path (LocalOnly run
	// mode); false in attach mode where list state is not
	// accessible from the operator's host.
	AllowList    []string
	DenyList     []string
	URLsLocal    bool
	URLsSelected int // index into AllowList++DenyList; -1 if empty

	// URLsUndo carries the most-recently-deleted URL pattern so the
	// operator can press Ctrl-Z to restore it. Single level — the
	// second delete overwrites the first. Cleared after a successful
	// restore exec or when the operator leaves the URLs panel
	// (closes #86).
	URLsUndo *URLsUndoEntry

	// URLsPendingReturn is set true by 'a'/'e' on the URLs pane: it
	// switches the bottom panel to the console for typing and the
	// next applyConsoleExec result snaps it back to the URLs panel
	// so the operator's flow is "press a/e → type → Enter → see new
	// list" without an extra hotkey. Cleared on panel-switch keys
	// (closes #86).
	URLsPendingReturn bool

	// OpsPausedTicks > 0 freezes TickResult / OpsTickResult ingestion
	// for N more ticks. Set by navigation keystrokes (j/k/Up/Down) in
	// approvals focus; decremented on each tick that arrives while
	// > 0; cleared on Tab/Shift-Tab or digit panel-switch so the
	// operator can read the info pane without the list churning
	// under them (closes #89).
	OpsPausedTicks int

	// GeneralizeOffer, when non-nil, surfaces the post-approve
	// "make this more general?" prompt: a specific allow entry
	// was just written for the named method+URL, and the operator
	// can press 1/2/3 to append a broader pattern (or any other
	// key to dismiss). Cleared after the next reducer step that
	// consumes or dismisses the offer (closes #85).
	GeneralizeOffer *GeneralizeOffer
}

// URLsUndoEntry carries the pattern + side (allow/deny) needed to
// reconstruct the most recent delete on the URLs panel (#86).
type URLsUndoEntry struct {
	Pattern string // raw pattern as stored in trollbridge.yaml (no leading verb)
	Side    string // "allow" or "deny"
}

// GeneralizeOffer carries the method+URL components of the
// just-approved request so the renderer can name the candidate
// broader patterns to the operator and the reducer can construct
// the chosen pattern (closes #85).
type GeneralizeOffer struct {
	Method string // uppercase HTTP verb
	URL    string // the specific URL just allowed
	Scheme string // "http" / "https" / "" (CONNECT)
	Host   string
	Port   int
	Path   string // including leading slash; "" for CONNECT
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

// URLsTickResult arrives after the runtime reloads the allow/deny
// lists from trollbridge.yaml in response to a CmdURLsRefresh.
// Local=false signals attach mode (no config path available); the
// renderer shows the attach-mode hint in that case. (#79)
type URLsTickResult struct {
	Allow []string
	Deny  []string
	Local bool
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
	// KeyShiftTab is xterm's CSI Z ("cursor backward tab"). With
	// today's two-pane focus model Tab and Shift-Tab are visually
	// identical (toggle); the distinct KeyCode lets a future
	// multi-pane focus cycle give Shift-Tab a "previous" direction
	// without re-wiring input parsing (closes #83).
	KeyShiftTab
	// KeyDelete is the Delete key (xterm CSI 3~). Distinct from
	// KeyBackspace, which covers the backspace+DEL pair (0x08/0x7f).
	// Used by the URLs pane to remove the selected entry (#86).
	KeyDelete
	// KeyCtrlZ is 0x1A. Used by the URLs pane to undo the most
	// recent delete (#86).
	KeyCtrlZ
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
func (URLsTickResult) event()    {}
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

// opsPauseTicks is how many tick refreshes a navigation keystroke
// suspends list ingestion for. At the ~1.5s tick cadence, 2 ticks ≈
// 3 seconds — long enough for the operator to read the info pane
// for the row they just landed on (#89).
const opsPauseTicks = 2

// CmdURLsRefresh asks the runtime to re-read the allow/deny lists
// from trollbridge.yaml and emit a URLsTickResult. Emitted on '4'
// open and after any console exec while the URLs pane is open
// (closes #79).
type CmdURLsRefresh struct{}

func (CmdNone) cmd()          {}
func (CmdRefresh) cmd()       {}
func (CmdApprove) cmd()       {}
func (CmdDeny) cmd()          {}
func (CmdQuit) cmd()          {}
func (CmdConsoleExec) cmd()   {}
func (CmdDigestRefresh) cmd() {}
func (CmdURLsRefresh) cmd()   {}
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
			reconcileDigestSelection(&m)
		}
		return m, CmdNone{}
	case URLsTickResult:
		if e.Err == nil {
			m.AllowList = e.Allow
			m.DenyList = e.Deny
			m.URLsLocal = e.Local
			total := len(m.AllowList) + len(m.DenyList)
			if total == 0 {
				m.URLsSelected = -1
			} else {
				if m.URLsSelected < 0 {
					m.URLsSelected = 0
				}
				if m.URLsSelected >= total {
					m.URLsSelected = total - 1
				}
			}
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
	if m.OpsPausedTicks > 0 {
		m.OpsPausedTicks--
		return m, CmdNone{}
	}
	prevKey := selectedRequestKey(m)
	m.Holds = e.Holds
	m.LastErr = ""
	preserveSelectionByRequestID(&m, prevKey)
	clampSelection(&m)
	return m, CmdNone{}
}

func applyOpsTick(m Model, e OpsTickResult) (Model, Cmd) {
	if e.Err != nil {
		m.LastErr = "control API (ops): " + truncate(e.Err.Error(), 200)
		return m, CmdNone{}
	}
	if m.OpsPausedTicks > 0 {
		m.OpsPausedTicks--
		return m, CmdNone{}
	}
	prevKey := selectedRequestKey(m)
	m.Ops = e.Ops
	m.LastErr = ""
	preserveSelectionByRequestID(&m, prevKey)
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

// selectedRequestKey returns the stable identifier (request_id or
// `hold:<holdID>`) of the operator's currently-selected row, or ""
// if no row is selected. Captured BEFORE m.Ops / m.Holds is replaced
// by a tick so the post-tick preserve-selection step can re-locate
// the same logical row in the new list (closes #89 part 2).
func selectedRequestKey(m Model) string {
	displayed := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(displayed) {
		return ""
	}
	key := displayed[m.Selected].RequestID
	if key == "" {
		key = "hold:" + displayed[m.Selected].HoldID
	}
	return key
}

// preserveSelectionByRequestID keeps the operator's selection on the
// same logical operation across refresh ticks (closes #39, #52, and
// #89). The caller passes prevKey — the key captured BEFORE the new
// m.Ops/m.Holds was written. If prevKey is empty there is no
// previously-selected row to track. If the new list does not contain
// the prevKey, Selected resets to -1; clampSelection moves it onto
// the head of the list afterwards.
func preserveSelectionByRequestID(m *Model, prevKey string) {
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
	// Generalize-offer prompt (#85): when set, intercept the
	// keystroke. 1/2/3 emit the broader pattern; any other key
	// (Esc, Enter, j/k, navigation) dismisses without writing.
	// The intent is "press a digit to take the offer; press
	// anything else to skip" — operators must not be trapped.
	if m.GeneralizeOffer != nil {
		offer := *m.GeneralizeOffer
		m.GeneralizeOffer = nil
		switch e.Rune {
		case '1':
			pat := generalizeAllMethodsForURL(offer)
			m.LastInfo = "appending allow: " + pat
			return m, CmdConsoleExec{Line: "allow " + pat}
		case '2':
			pat := generalizeAllURLsForMethod(offer)
			m.LastInfo = "appending allow: " + pat
			return m, CmdConsoleExec{Line: "allow " + pat}
		case '3':
			pat := generalizeAnyMethodAnyURL(offer)
			m.LastInfo = "appending allow: " + pat
			return m, CmdConsoleExec{Line: "allow " + pat}
		default:
			// Dismissed; fall through to normal dispatch so the
			// keystroke still does its usual thing (operator
			// doesn't lose a Tab / j / Esc to the prompt).
			//
			// Exception: Esc alone should NOT also close the bottom
			// panel (#87) — a single Esc dismisses the offer; a
			// second Esc closes the panel.
			m.LastInfo = "generalize prompt dismissed"
			if e.Key == KeyEsc {
				return m, CmdNone{}
			}
		}
	}
	// Esc closes the bottom panel when one is open; never quits the
	// app (#87). Quit is `q` or Ctrl-C only.
	if e.Key == KeyEsc {
		if m.BottomPanelOpen {
			m.BottomPanelOpen = false
			m.DigestExpanded = false
			m.Focused = PaneApprovals
			m.URLsPendingReturn = false
			return m, CmdNone{}
		}
		return m, CmdNone{}
	}
	if e.Key == KeyTab || e.Key == KeyShiftTab {
		// Tab cycles focus to the bottom pane only when something is
		// down there to focus on. Pre-#66-reactivation, Tab toggled
		// unconditionally; the new default has no bottom pane to focus
		// when BottomPanelOpen is false, so Tab is a no-op then.
		//
		// Shift-Tab is the reverse direction (#83). Today there are
		// only two focus targets (PaneApprovals, PaneConsole), so
		// forward and backward converge on the same toggle. When a
		// future job introduces a third pane, the cycle becomes
		// `(idx + 1) mod n` for Tab and `(idx - 1 + n) mod n` for
		// Shift-Tab — both reading from the same dispatch.
		if !m.BottomPanelOpen {
			return m, CmdNone{}
		}
		if m.Focused == PaneApprovals {
			m.Focused = PaneConsole
		} else {
			m.Focused = PaneApprovals
		}
		// Operator changing focus is the explicit "release the pause"
		// signal (#89): they're done navigating; resume tick ingestion.
		m.OpsPausedTicks = 0
		return m, CmdNone{}
	}
	// Pane-specific dispatch.
	if m.Focused == PaneConsole {
		if m.BottomPanel == BottomPanelURLs {
			return applyKeyURLs(m, e)
		}
		if m.BottomPanel == BottomPanelLLM {
			return applyKeyLLM(m, e)
		}
		return applyKeyConsole(m, e)
	}
	return applyKeyApprovals(m, e)
}

// reconcileDigestSelection keeps the operator's LLM-panel selection
// on the same digest across DigestTickResult updates. The ring is
// keyed by RequestID; index-based selection drifts when the ring
// evicts an old entry or re-orders during a snapshot (insight 12).
// If the previously-selected RequestID is no longer present, fall
// back to the newest digest, or the empty string when the list is
// empty.
func reconcileDigestSelection(m *Model) {
	if len(m.Digests) == 0 {
		m.DigestSelected = ""
		m.DigestExpanded = false
		return
	}
	if m.DigestSelected != "" {
		for _, d := range m.Digests {
			if d.RequestID == m.DigestSelected {
				return
			}
		}
	}
	m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID
	// Expand-by-default (#91): the new fallback selection inherits
	// the same default-expanded state as the open path.
	m.DigestExpanded = true
}

// digestSelectedIndex returns the index of the selected digest in
// newest-first display order, or -1 if there is no selection or it
// has been evicted. Newest-first order matches the renderer's
// iteration.
func digestSelectedIndex(m Model) int {
	if m.DigestSelected == "" || len(m.Digests) == 0 {
		return -1
	}
	for i := len(m.Digests) - 1; i >= 0; i-- {
		if m.Digests[i].RequestID == m.DigestSelected {
			return (len(m.Digests) - 1) - i
		}
	}
	return -1
}

// digestAtDisplayIndex returns the digest at the given newest-first
// display index, or false if out of range.
func digestAtDisplayIndex(m Model, idx int) (advisor.Digest, bool) {
	if idx < 0 || idx >= len(m.Digests) {
		return advisor.Digest{}, false
	}
	return m.Digests[len(m.Digests)-1-idx], true
}

// applyKeyLLM handles keystrokes when the LLM bottom panel is open
// and focused (closes #81). Navigation moves the selection cursor
// over the digest list; Enter toggles the per-digest detail view.
// The renderer decides inline-vs-modal layout based on whether the
// detail block fits in the panel's available rows.
func applyKeyLLM(m Model, e KeyEvent) (Model, Cmd) {
	if e.Key == KeyEsc {
		// Esc collapses an expanded detail; if nothing is expanded,
		// Esc defocuses back to approvals (matches applyKeyURLs and
		// applyKeyConsole — Esc inside a panel "backs out").
		if m.DigestExpanded {
			m.DigestExpanded = false
			return m, CmdNone{}
		}
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	if e.Rune == 'q' {
		// `q` defocuses (does not quit the TUI); quitting still
		// works from approvals focus.
		m.DigestExpanded = false
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	// Hotkey toggle: `0` closes the panel, `3` toggles it closed.
	// Mirrors applyKeyURLs' digit handling so the operator can close
	// the panel without first defocusing.
	if e.Rune == '0' || e.Rune == '3' {
		m.BottomPanelOpen = false
		m.DigestExpanded = false
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	if e.Key == KeyEnter {
		// Enter toggles the per-digest detail view. Inline vs modal
		// is a render decision — the reducer only tracks the binary
		// "expanded" state.
		if m.DigestSelected == "" {
			return m, CmdNone{}
		}
		m.DigestExpanded = !m.DigestExpanded
		return m, CmdNone{}
	}
	if e.Key == KeyUp || e.Rune == 'k' {
		// Up/k moves toward newer digests. The new selection auto-
		// expands (#91) — operator never has to press Enter to see
		// the detail.
		idx := digestSelectedIndex(m)
		if idx > 0 {
			if d, ok := digestAtDisplayIndex(m, idx-1); ok {
				m.DigestSelected = d.RequestID
			}
		} else if idx < 0 && len(m.Digests) > 0 {
			m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID
		}
		m.DigestExpanded = true
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		idx := digestSelectedIndex(m)
		if idx >= 0 && idx < len(m.Digests)-1 {
			if d, ok := digestAtDisplayIndex(m, idx+1); ok {
				m.DigestSelected = d.RequestID
			}
		} else if idx < 0 && len(m.Digests) > 0 {
			m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID
		}
		m.DigestExpanded = true
		return m, CmdNone{}
	}
	return m, CmdNone{}
}

// applyKeyURLs handles keystrokes when the URLs pane is open and
// focused. The pane is the allow/deny list editor (closes #79):
// j/k or Up/Down navigate across allow→deny, x removes the
// selected entry through the existing console.Backend remove
// path, Esc defocuses back to approvals.
func applyKeyURLs(m Model, e KeyEvent) (Model, Cmd) {
	if e.Key == KeyEsc {
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	combinedLen := len(m.AllowList) + len(m.DenyList)
	if e.Key == KeyUp || e.Rune == 'k' {
		if m.URLsSelected > 0 {
			m.URLsSelected--
		}
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		if m.URLsSelected < combinedLen-1 {
			m.URLsSelected++
		}
		return m, CmdNone{}
	}
	if e.Rune == 'x' || e.Key == KeyDelete {
		return urlsRemoveSelected(m)
	}
	if e.Key == KeyCtrlZ {
		return urlsUndo(m)
	}
	if e.Rune == 'a' {
		return urlsMoveTo(m, "allow")
	}
	if e.Rune == 'd' {
		return urlsMoveTo(m, "deny")
	}
	if e.Rune == '+' {
		return urlsEnterAddMode(m)
	}
	if e.Rune == 'e' {
		return urlsEnterEditMode(m)
	}
	if e.Rune == 'g' {
		return urlsGeneralize(m)
	}
	return m, CmdNone{}
}

// urlsMoveTo implements the URLs-panel 'a' (approve, move to allow)
// and 'd' (deny, move to deny) verbs. When the selected entry is
// already on the destination side the call surfaces an info-row
// message and emits no console command (#86).
func urlsMoveTo(m Model, side string) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	pattern, currentSide, ok := urlsSelectedPattern(m)
	if !ok {
		m.LastErr = "no entry selected"
		return m, CmdNone{}
	}
	if currentSide == side {
		m.LastInfo = pattern + " already in " + side
		return m, CmdNone{}
	}
	m.LastInfo = "moving " + pattern + " to " + side + "…"
	return m, CmdConsoleExec{Line: "move " + side + " " + pattern}
}

// urlsSelectedPattern returns the pattern + side of the currently
// selected URLs-panel row, or ("", "", false) if the selection is
// out of range or points at a non-entry (blank/comment, defensively
// — m.AllowList/DenyList are pre-filtered).
func urlsSelectedPattern(m Model) (pattern, side string, ok bool) {
	combinedLen := len(m.AllowList) + len(m.DenyList)
	if m.URLsSelected < 0 || m.URLsSelected >= combinedLen {
		return "", "", false
	}
	if m.URLsSelected < len(m.AllowList) {
		pattern = m.AllowList[m.URLsSelected]
		side = "allow"
	} else {
		pattern = m.DenyList[m.URLsSelected-len(m.AllowList)]
		side = "deny"
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return "", "", false
	}
	return pattern, side, true
}

func urlsRemoveSelected(m Model) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	pattern, side, ok := urlsSelectedPattern(m)
	if !ok {
		m.LastErr = "no entry selected"
		return m, CmdNone{}
	}
	m.URLsUndo = &URLsUndoEntry{Pattern: pattern, Side: side}
	m.LastInfo = "removing " + pattern + "… (^z undoes)"
	return m, CmdConsoleExec{Line: "remove " + pattern}
}

func urlsUndo(m Model) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	if m.URLsUndo == nil {
		m.LastErr = "nothing to undo"
		return m, CmdNone{}
	}
	u := *m.URLsUndo
	m.URLsUndo = nil
	m.LastInfo = "restoring " + u.Pattern + "…"
	return m, CmdConsoleExec{Line: u.Side + " " + u.Pattern}
}

func urlsEnterAddMode(m Model) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	prefill := []rune("allow ")
	m.BottomPanel = BottomPanelConsole
	m.URLsPendingReturn = true
	m.Console.Input = prefill
	m.Console.Cursor = len(prefill)
	m.LastInfo = "add: type a URL pattern and press Enter (Esc to cancel)"
	return m, CmdNone{}
}

func urlsEnterEditMode(m Model) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	pattern, side, ok := urlsSelectedPattern(m)
	if !ok {
		m.LastErr = "no entry selected"
		return m, CmdNone{}
	}
	// Remove the original now so the operator sees the slot empty
	// while they type the replacement; Ctrl-Z restores if they Esc
	// out without committing.
	m.URLsUndo = &URLsUndoEntry{Pattern: pattern, Side: side}
	prefill := []rune(side + " " + pattern)
	m.BottomPanel = BottomPanelConsole
	m.URLsPendingReturn = true
	m.Console.Input = prefill
	m.Console.Cursor = len(prefill)
	m.LastInfo = "edit: change and Enter, or Esc + ^z to recover"
	// The remove fires now; the operator's typed line fires on Enter.
	return m, CmdConsoleExec{Line: "remove " + pattern}
}

func urlsGeneralize(m Model) (Model, Cmd) {
	pattern, _, ok := urlsSelectedPattern(m)
	if !ok {
		m.LastErr = "no entry selected"
		return m, CmdNone{}
	}
	offer, ok := buildGeneralizeOfferFromPattern(pattern)
	if !ok {
		m.LastErr = "generalize requires a concrete method+URL entry"
		return m, CmdNone{}
	}
	m.GeneralizeOffer = offer
	return m, CmdNone{}
}

// buildGeneralizeOfferFromPattern parses a stored URL-list pattern
// of the form `[METHOD ]URL` (with `*` allowed in the METHOD slot)
// into a GeneralizeOffer the existing approve-flow generalize code
// can consume. Patterns containing wildcards in the URL are
// rejected — the three generalize axes are only well-defined for
// concrete URLs.
func buildGeneralizeOfferFromPattern(pat string) (*GeneralizeOffer, bool) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, false
	}
	method := "*"
	url := pat
	if i := strings.IndexByte(pat, ' '); i > 0 {
		head := pat[:i]
		if head == "*" || isAllUpperASCII(head) {
			method = head
			url = strings.TrimSpace(pat[i+1:])
		}
	}
	if url == "" {
		return nil, false
	}
	// Require a scheme — CONNECT-style host:port patterns don't have
	// a path axis to generalize.
	if !strings.Contains(url, "://") {
		return nil, false
	}
	// Reject wildcards in the URL — generalize is for concrete entries.
	if strings.Contains(url, "*") {
		return nil, false
	}
	scheme, hostport, path := splitURL(url)
	host, port := splitHostPort(hostport)
	if host == "" {
		return nil, false
	}
	return &GeneralizeOffer{
		Method: method,
		URL:    url,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Path:   path,
	}, true
}

func isAllUpperASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func applyKeyApprovals(m Model, e KeyEvent) (Model, Cmd) {
	if e.Rune == 'q' {
		m.Quit = true
		return m, CmdQuit{}
	}
	displayed := DisplayedOps(m)
	if e.Key == KeyUp || e.Rune == 'k' {
		if m.Selected > 0 {
			m.Selected--
		}
		// Pause the auto-refresh while the operator is navigating
		// (#89): the list (and the info pane that mirrors the
		// selected op) must not churn under them while they read.
		m.OpsPausedTicks = opsPauseTicks
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		if m.Selected < len(displayed)-1 {
			m.Selected++
		}
		m.OpsPausedTicks = opsPauseTicks
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
	//
	// Any explicit panel choice cancels a URLs-pending-return: if
	// the operator opened a/e mode and then manually picked another
	// panel, the next exec must not yank them back to URLs (#86).
	// It also releases the nav-pause (#89): explicit panel choice
	// means the operator is done reading the approvals list.
	if e.Rune >= '0' && e.Rune <= '4' {
		m.URLsPendingReturn = false
		m.OpsPausedTicks = 0
	}
	switch e.Rune {
	case '0':
		m.BottomPanelOpen = false
		// If the operator had Tabbed into the bottom pane before
		// hiding it, snap focus back to approvals — there is no
		// visible pane to keep focus on.
		m.Focused = PaneApprovals
		// Cancel any URLs-pending-return so the next exec does not
		// surprise the operator by re-opening URLs (#86).
		m.URLsPendingReturn = false
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
			m.DigestExpanded = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelLLM
		m.BottomPanelOpen = true
		// Auto-focus the LLM pane so j/k/Up/Down/Enter reach
		// applyKeyLLM without an explicit Tab. Matches the URLs
		// auto-focus precedent (#79); the LLM panel is now
		// interactively browseable (closes #81).
		m.Focused = PaneConsole
		// Initialize the selection to the newest digest if the
		// existing selection has been evicted or is empty. The
		// refresh below will reconcile against the freshly-fetched
		// list.
		if m.DigestSelected == "" && len(m.Digests) > 0 {
			m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID
		}
		// Default to expanded so the operator sees the detail block
		// immediately, without an Enter dance (#91).
		m.DigestExpanded = true
		return m, CmdDigestRefresh{}
	case '4':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelURLs {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}
		}
		m.BottomPanel = BottomPanelURLs
		m.BottomPanelOpen = true
		// Auto-focus the URLs pane so j/k/x reach applyKeyURLs
		// without an explicit Tab — the pane is editable (closes
		// #79). Lifts the narrowed reading from #77 (which had
		// kept '4' on approvals focus).
		m.Focused = PaneConsole
		return m, CmdURLsRefresh{}
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
			target := op.Method + " " + op.URL
			if e.Rune == 'a' {
				m.LastInfo = "approving " + target + "…"
				return m, CmdApprove{ID: op.HoldID}
			}
			m.LastInfo = "denying " + target + "…"
			return m, CmdDeny{ID: op.HoldID}
		}
		// Retroactive add to allow / deny list (closes #60). Routed
		// through the console pane so the same configwrite + oplog
		// shape runs as if the operator had typed `allow <url>`.
		// Pattern now carries the method prefix (#85) so subsequent
		// generalization options can swap the method axis without
		// ambiguity.
		if op.URL == "" {
			m.LastErr = "selected row has no URL to add"
			return m, CmdNone{}
		}
		verb := "allow"
		if e.Rune == 'd' {
			verb = "deny"
		}
		method := strings.ToUpper(strings.TrimSpace(op.Method))
		if method == "" {
			method = "*"
		}
		specific := method + " " + op.URL
		m.LastInfo = verb + "ing " + specific + "…"
		// On allow, queue the generalize-offer prompt — operator
		// can press 1/2/3 on the next keystroke to also write a
		// broader pattern. Deny does not get the offer (denies are
		// usually intentional and operator-narrow); revisit if
		// requested.
		if e.Rune == 'a' {
			if offer, ok := buildGeneralizeOffer(op); ok {
				m.GeneralizeOffer = offer
			}
		}
		return m, CmdConsoleExec{Line: verb + " " + specific}
	}
	return m, CmdNone{}
}

// buildGeneralizeOffer parses the op's URL into its components so
// the generalize-prompt renderer can name the broader patterns
// and the reducer can construct them. Returns (nil, false) when
// the URL is empty or unparseable — the prompt is skipped.
func buildGeneralizeOffer(op DisplayedOp) (*GeneralizeOffer, bool) {
	if op.URL == "" {
		return nil, false
	}
	method := strings.ToUpper(strings.TrimSpace(op.Method))
	if method == "" {
		method = "*"
	}
	scheme, hostport, path := splitURL(op.URL)
	host, port := splitHostPort(hostport)
	return &GeneralizeOffer{
		Method: method,
		URL:    op.URL,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Path:   path,
	}, true
}

// splitURL breaks "scheme://host[:port]/path" or "host[:port]"
// (CONNECT-style) into (scheme, hostport, path). scheme is empty
// for CONNECT-style.
func splitURL(u string) (scheme, hostport, path string) {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = rest[:i]
		rest = rest[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport = rest[:i]
		path = rest[i:]
	} else {
		hostport = rest
	}
	return scheme, hostport, path
}

// splitHostPort parses "host:port" or "host". Returns port=0 when
// absent or unparseable.
func splitHostPort(hp string) (host string, port int) {
	host = hp
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		host = hp[:i]
		if v, err := strconv.Atoi(hp[i+1:]); err == nil {
			port = v
		}
	}
	return host, port
}

// generalizeAllMethodsForURL returns the pattern that allows any
// method on the same URL — i.e., replaces the method prefix with
// `*` while keeping scheme/host/port/path unchanged.
func generalizeAllMethodsForURL(o GeneralizeOffer) string {
	return "* " + o.URL
}

// generalizeAllURLsForMethod returns the pattern that allows any
// URL on the same host:port (path becomes `/*`) with the original
// method retained.
func generalizeAllURLsForMethod(o GeneralizeOffer) string {
	return o.Method + " " + formatHostBase(o) + "/*"
}

// generalizeAnyMethodAnyURL returns the pattern that allows any
// method on any URL of the same host:port.
func generalizeAnyMethodAnyURL(o GeneralizeOffer) string {
	return "* " + formatHostBase(o) + "/*"
}

// formatHostBase returns "<scheme>://<host>:<port>" or its
// CONNECT-style equivalent "<host>:<port>" when the original URL
// had no scheme.
func formatHostBase(o GeneralizeOffer) string {
	if o.Scheme == "" {
		if o.Port == 0 {
			return o.Host
		}
		return fmt.Sprintf("%s:%d", o.Host, o.Port)
	}
	if o.Port == 0 {
		return fmt.Sprintf("%s://%s", o.Scheme, o.Host)
	}
	return fmt.Sprintf("%s://%s:%d", o.Scheme, o.Host, o.Port)
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
	target := resolveActionTarget(m, e.ID)
	if e.Err != nil {
		// Surface what the operator just did — URL is more meaningful
		// than the queue id when something goes wrong (#92).
		idForErr := target
		if idForErr == "" {
			idForErr = e.ID
		}
		m.LastErr = e.Action + " " + idForErr + ": " + truncate(e.Err.Error(), 200)
		m.LastInfo = ""
		return m, CmdNone{}
	}
	// Optimistically remove the resolved hold; the next tick re-
	// fetches the authoritative list anyway. The corresponding ops
	// entry will transition to its terminal status on the next ops
	// tick when writeAudit fires.
	m.Holds = removeHold(m.Holds, e.ID)
	if target != "" {
		m.LastInfo = e.Action + "d " + target
	} else {
		// Ring may have rotated; fall back to the verb alone rather
		// than surfacing a hold id the operator does not care about.
		m.LastInfo = e.Action + "d (op no longer in ring)"
	}
	m.LastErr = ""
	clampSelection(&m)
	return m, CmdRefresh{}
}

// resolveActionTarget looks up the displayed op carrying holdID and
// returns "<METHOD> <URL>" for use in operator-facing status messages
// (#92). Empty string when the op is not in the ring.
func resolveActionTarget(m Model, holdID string) string {
	if holdID == "" {
		return ""
	}
	for _, o := range DisplayedOps(m) {
		if o.HoldID == holdID {
			return o.Method + " " + o.URL
		}
	}
	return ""
}

func applyConsoleExec(m Model, e ConsoleExecResult) (Model, Cmd) {
	for _, line := range splitLines(e.Output) {
		m.Console = appendScrollback(m.Console, line)
	}
	if e.Quit {
		m.Quit = true
		return m, CmdQuit{}
	}
	// If the operator entered a/e mode from the URLs panel, snap the
	// bottom panel back to URLs on exec completion — they expect to
	// see the new list, not stay on the console. The refresh below
	// then fires because BottomPanel is URLs again (#86).
	if m.URLsPendingReturn {
		m.URLsPendingReturn = false
		m.BottomPanel = BottomPanelURLs
	}
	// After any console exec, refresh the URLs pane if it's open —
	// allow/deny/remove and #79's x-removes-selected all touch the
	// lists, and the operator should see the post-mutation state
	// without an extra refresh keystroke.
	if m.BottomPanelOpen && m.BottomPanel == BottomPanelURLs {
		return m, CmdURLsRefresh{}
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
