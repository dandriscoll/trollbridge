// Package tui hosts the unified two-pane operator UI: an approvals
// pane (top) listing pending holds, and a console pane (bottom) for
// allow/deny/list/remove/reload/test/doctor/help/quit commands. The
// reducer in this file is a pure function from (model, event) to
// (model, command); the runtime in approvals.go merges three event
// sources (key input, refresh ticks, action-result callbacks) and
// drives the reducer.
package tui

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/dandriscoll/trollbridge/internal/generalize"
	"github.com/dandriscoll/trollbridge/internal/opstream"
	"github.com/dandriscoll/trollbridge/internal/reloadstatus"
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

	// statusInfoSeen / statusInfoAge time out a lingering LastInfo line
	// (#180): the ops tick ages the currently-shown LastInfo and clears
	// it after statusInfoTimeoutTicks. seen tracks the last value so a
	// fresh message resets the age. Unexported — reducer-internal.
	statusInfoSeen string
	statusInfoAge  int
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

	// URLsAnchor is the fixed end of a shift-select range in the URLs
	// pane (#170 multi-select). -1 means no multi-selection; otherwise
	// the selected set is the inclusive range
	// [min(URLsAnchor,URLsSelected), max(...)]. Seeded from the cursor
	// on the first Shift-Up/Down and reset to -1 on any plain
	// navigation or list edit. Stored as an index range rather than a
	// set so the value-copied Model carries no shared mutable map.
	URLsAnchor int

	// GenCard is the active generalization candidate card (#170),
	// shown in the operations pane. nil when no card is up. While
	// non-nil the card is modal: a/d/tab/esc act on the card.
	GenCard *GeneralizeCard

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

	// LastInputTicks counts ticks since the operator's last key
	// event. Reset to 0 on every keypress; incremented in
	// applyOpsTick. When it reaches idleSnapTicks AND a pending
	// row exists AND the cursor is NOT already on a pending row,
	// the cursor snaps to the bottommost row (newest pending) so
	// idle operators don't miss new work (#156). One-shot per
	// idle window — the counter resets to 0 after a snap.
	LastInputTicks int

	// TickCount is a monotonic ops-tick counter driving per-row
	// animation (e.g. the LLM-checking spinner — #192). Advanced by
	// applyOpsTick only when the tick is not paused (OpsPausedTicks
	// would otherwise let the spinner spin while the rest of the pane
	// is frozen). Reading-only outside the reducer; the renderer
	// derives a frame index from this value.
	TickCount int

	// History, when non-nil, is consulted at row-render time to detect
	// decision reversals on a host (closes #192). Wired by the in-
	// process client from the policy engine's sliding-window history;
	// attach mode passes nil — reversal coloring then degrades to
	// off.
	History DecisionHistorySource

	// GeneralizeOffer was the post-approve 1/2/3 keystroke prompt
	// added by #85 and removed by #168 (the daemon-owned quiet-
	// moment suggestion lifecycle replaced it). The field is gone;
	// the struct definition and helper functions are also gone.
	// Suggestion is the active row offered in the pending area
	// when the daemon's detector finds an opportunity at a quiet
	// moment. Hidden whenever Holds is non-empty.
	Suggestion *Suggestion

	// ReloadStatus carries the daemon's most-recent hot-reload
	// outcome (closes #129). Polled from /v1/rules on each refresh
	// tick; populated from ReloadTickResult by the reducer. The
	// approvals-pane header renders a bold-red `␇ reload failed`
	// badge when ReloadStatus.LastError is non-empty.
	ReloadStatus reloadstatus.Status
}

// URLsUndoEntry carries the pattern + side (allow/deny) needed to
// reconstruct the most recent delete on the URLs panel (#86).
type URLsUndoEntry struct {
	Pattern string // raw pattern as stored in trollbridge.yaml (no leading verb)
	Side    string // "allow" or "deny"
}

// Suggestion is the TUI's view of the daemon's currently-offered
// quiet-moment generalization suggestion (#168). The full lifecycle
// lives in internal/suggestion; the TUI is a viewer. The Suggestion
// row is rendered in the approvals pane below any pending holds
// and hidden when Holds is non-empty.
type Suggestion struct {
	ID               string
	Axis             string
	List             string // "allow" or "deny"
	SourceEntries    []string
	SuggestedPattern string
	Reason           string
	AxesRemaining    int
}

// GeneralizeCard is the unified generalization candidate surface shown
// in the operations pane (#170). The three entry points (single-select
// `g`, multi-select `g`, and — filed for a follow-up — the LLM suggest)
// all populate this one card. Candidates is the axis options for the
// current trigger; AxisIndex selects which is shown and `tab` cycles
// it. SourceDesc names what the candidate was derived from (e.g. "1
// entry: GET …" or "3 selected entries"). The card is modal while up.
type GeneralizeCard struct {
	Candidates []generalize.Candidate
	AxisIndex  int
	SourceDesc string
}

// Current returns the candidate the card is presently showing.
func (c *GeneralizeCard) Current() generalize.Candidate {
	return c.Candidates[c.AxisIndex]
}

// AlertsState carries the chime toggle plus the last pending count
// observed by the reducer (so the chime fires only on transitions
// UP, not on every tick that has pending requests).
type AlertsState struct {
	ChimeEnabled    bool
	LastPendingSeen int
}

// Selection is the unified per-panel cursor abstraction (closes
// #112). Each bottom panel tracks its own cursor: approvals + URLs
// use Index (positional, into the displayed slice), LLM uses Key
// (RequestID, since the digest ring re-orders and indices drift).
//
// The model still exposes the per-panel fields (Selected,
// URLsSelected, DigestSelected) for backward-compatibility with
// existing callers; a future job can migrate those fields onto a
// Selections map[BottomPanel]Selection if a sixth panel arrives or
// the per-field shape becomes a maintenance burden. The constructor
// helpers below let callers read a per-panel selection through the
// abstraction without committing to the map shape now.
type Selection struct {
	Index int    // -1 when empty; valid index otherwise
	Key   string // empty when no key-based identity (approvals + URLs); RequestID for LLM
}

// SelectionFor returns the current selection for the named panel.
// Reads from the model's existing per-panel fields so the
// abstraction is a non-breaking addition; callers can switch to
// this accessor at their own pace, and the underlying field
// migration can land later without breaking the API.
func (m Model) SelectionFor(p BottomPanel) Selection {
	switch p {
	case BottomPanelLLM:
		return Selection{Index: -1, Key: m.DigestSelected}
	case BottomPanelURLs:
		return Selection{Index: m.URLsSelected}
	default:
		// Approvals + Console + Info share m.Selected as the upper-
		// pane index; the lower panels (Console, Info) have no
		// per-panel cursor today and return -1.
		if p == BottomPanelConsole || p == BottomPanelInfo {
			return Selection{Index: -1}
		}
		return Selection{Index: m.Selected}
	}
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

// ReloadTickResult arrives after a poll of /v1/rules' reload-status
// fields completes (closes #129). The reducer drops the carried
// Status into Model.ReloadStatus; the approvals-pane renderer reads
// it to drive the failed-reload badge.
//
// A non-nil Err means the poll itself failed (network, transport).
// The reducer treats that as "keep the previous status" — a
// transport blip should not flip the badge state.
type ReloadTickResult struct {
	Status reloadstatus.Status
	Err    error
}

// SuggestionTickResult arrives after a poll of /v1/suggestion (#172).
// Suggestion is nil when the daemon has no active offer; a non-nil Err
// (transport blip) means "keep the prior state" so the card does not
// flicker.
type SuggestionTickResult struct {
	Suggestion *Suggestion
	Err        error
	// OnDemand marks a result from a CmdSuggestNow scan (#174) rather
	// than the periodic poll, so an empty result can surface a "no
	// opportunities" message instead of silently clearing the card.
	OnDemand bool
}

// SuggestionActionResult arrives after a CmdSuggestionAccept /
// CmdSuggestionDecline completes (#172). Action is "accept" or
// "decline"; Err is non-nil when the control call failed (e.g. the
// suggestion went stale).
type SuggestionActionResult struct {
	Action string
	Err    error
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
	// KeyCtrlL is 0x0C. Triggers a hard repaint — matches vi's ^L
	// to sweep stray bytes that may have landed on the alt-screen
	// (#115).
	KeyCtrlL
	// KeyShiftUp / KeyShiftDown are the modifier-CSI arrow forms
	// (xterm `ESC [ 1 ; 2 A` / `... B`). Distinct KeyCodes so the
	// parser can consume the whole sequence without leaking the
	// `; 2 A` tail as printable runes (#171). They are inert today;
	// issue #170 gives them multi-select meaning in the URLs pane.
	KeyShiftUp
	KeyShiftDown
	// KeyHome / KeyEnd jump the cursor to the first / last row of
	// the focused list panel (#196). Terminals send Home as either
	// `ESC [ H` or `ESC [ 1 ~` and End as `ESC [ F` or `ESC [ 4 ~`;
	// csiKeyEvent maps all four forms to these KeyCodes.
	KeyHome
	KeyEnd
)

// ActionResult arrives after an approve or deny POST completes.
// Method/URL carry the acted-on request so that a hold-not-found
// failure can fall back to writing the URL to the allow/deny list
// (#184) — the hold is a transient pointer; the operator's intent to
// allow/deny the URL stands even when the hold has already been
// resolved out from under them.
type ActionResult struct {
	ID     string
	Action string // "approve" | "deny"
	Method string
	URL    string
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
func (ReloadTickResult) event()     {}
func (SuggestionTickResult) event()   {}
func (SuggestionActionResult) event() {}
func (KeyEvent) event()          {}
func (ActionResult) event()      {}
func (ResizeEvent) event()       {}
func (ConsoleExecResult) event() {}

// Cmd is the side-effect the reducer requests of the runtime.
type Cmd interface{ cmd() }

type CmdNone struct{}
type CmdRefresh struct{}
// CmdApprove / CmdDeny carry the acted-on request's Method and URL
// alongside the hold id so the action-result handler can fall back to
// an allow/deny-list write when the hold has already been resolved
// (#184).
type CmdApprove struct {
	ID     string
	Method string
	URL    string
}
type CmdDeny struct {
	ID     string
	Method string
	URL    string
}

// CmdRingBell is emitted on the tick where the pending count
// transitions up (e.g. 0→1 or 2→3) and the chime is enabled. The
// runtime writes a single BEL byte to the TUI output stream;
// terminal emulators then beep / flash per their own settings.
type CmdRingBell struct{}
type CmdQuit struct{}
type CmdConsoleExec struct{ Line string }

// CmdGeneralizeAccept applies an accepted generalization card (#170):
// the runtime removes the more-specific Sources and adds Pattern to
// List in one atomic write (#173), serialized through the same console
// worker as CmdConsoleExec.
type CmdGeneralizeAccept struct {
	List    string // "allow" or "deny"
	Pattern string
	Sources []string
}
type CmdDigestRefresh struct{}

// CmdSuggestionAccept / CmdSuggestionDecline resolve the daemon's
// active quiet-moment suggestion through the control plane (#172). The
// runtime calls the ControlClient off the event loop and emits a
// SuggestionActionResult; the next poll refreshes Model.Suggestion.
type CmdSuggestionAccept struct{ ID string }
type CmdSuggestionDecline struct{ ID string }

// CmdSuggestNow asks the daemon to run the generalization detector on
// demand (#174). The runtime calls the ControlClient off the event
// loop and emits a SuggestionTickResult{OnDemand:true}.
type CmdSuggestNow struct{}

// CmdRepaint is emitted on Ctrl-L. The runtime writes a hard-clear
// sequence (clear visible + scrollback, home cursor, hide cursor)
// before the next render so stray bytes leaked onto the alt-screen
// are swept (#115).
type CmdRepaint struct{}

// CmdSuspend is emitted on `z` from the approvals pane (#176). The
// runtime restores the cooked terminal and raises SIGTSTP so the host
// shell regains control; on resume it re-enters raw mode + the
// alt-screen and repaints. No-op when the runtime wired no suspend
// handler (tests, or platforms without job control).
type CmdSuspend struct{}

// opsPauseTicks is how many tick refreshes a navigation keystroke
// suspends list ingestion for. At the ~1.5s tick cadence, 2 ticks ≈
// 3 seconds — long enough for the operator to read the info pane
// for the row they just landed on (#89).
const opsPauseTicks = 2

// idleSnapTicks is how long the operator must be idle (no key
// events) before the cursor snaps to the newest pending row. At
// the ~1.5s tick cadence, 4 ticks ≈ 6s — long enough that an
// operator actively navigating doesn't get yanked, short enough
// that returning attention to the pane finds the cursor already
// on actionable work (#156).
const idleSnapTicks = 4

// statusInfoTimeoutTicks is how long a transient info status (LastInfo,
// e.g. "generalized → allow GET …") stays at the bottom of the pane
// before it clears. At the ~1.5s ops-tick cadence, 8 ticks ≈ 12s —
// long enough to read, short enough that it doesn't sit there for
// minutes (#180). LastErr already clears on the next successful tick.
const statusInfoTimeoutTicks = 8

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
func (CmdConsoleExec) cmd()       {}
func (CmdGeneralizeAccept) cmd()   {}
func (CmdSuggestionAccept) cmd()   {}
func (CmdSuggestionDecline) cmd()  {}
func (CmdSuggestNow) cmd()         {}
func (CmdDigestRefresh) cmd() {}
func (CmdURLsRefresh) cmd()   {}
func (CmdRingBell) cmd()      {}
func (CmdRepaint) cmd()       {}
func (CmdSuspend) cmd()       {}

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
			// A list reload invalidates any in-flight multi-selection
			// range (indices may have shifted under add/remove). Reset
			// the anchor so a stale range never feeds `g` (#170). This
			// is also the chokepoint that clears the zero-value anchor
			// when the pane first opens via CmdURLsRefresh.
			m.URLsAnchor = -1
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
	case ReloadTickResult:
		// Transport-level failure: keep the previous status so a
		// blip in the control-plane fetch does not flip the badge.
		// A real reload failure surfaces via Status.LastError, not
		// via Err.
		if e.Err == nil {
			m.ReloadStatus = e.Status
		}
		return m, CmdNone{}
	case SuggestionTickResult:
		// Keep prior state on a transport blip (#172) — same rule as
		// ReloadTickResult — so the ambient card does not flicker.
		if e.Err == nil {
			m.Suggestion = e.Suggestion
		}
		if e.OnDemand {
			// On-demand scan (#174) gives explicit feedback rather than
			// silently leaving the card empty.
			if e.Err != nil {
				m.LastErr = "suggest: " + truncate(e.Err.Error(), 200)
			} else if e.Suggestion == nil {
				m.LastInfo = "no generalization opportunities found"
			} else {
				m.LastInfo = ""
			}
		}
		return m, CmdNone{}
	case SuggestionActionResult:
		if e.Err != nil {
			m.LastErr = "suggestion " + e.Action + ": " + truncate(e.Err.Error(), 200)
			m.LastInfo = ""
		} else {
			m.LastInfo = "suggestion " + suggestionActionPast(e.Action)
			m.LastErr = ""
			// Clear optimistically; the next poll re-fetches the
			// authoritative active suggestion (likely nil now).
			m.Suggestion = nil
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

// suggestionActionPast renders a suggestion action verb in past tense
// for the status line. The verbs end in "e", so a bare "+ed" suffix
// produced "declineed" (#187); map the known verbs explicitly.
func suggestionActionPast(action string) string {
	switch action {
	case "accept":
		return "accepted"
	case "decline":
		return "declined"
	default:
		return action + "ed"
	}
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
	prevGroup, prevReq, wasOnPending := selectionAnchors(m)
	m.Holds = e.Holds
	m.LastErr = ""
	preserveSelection(&m, prevGroup, prevReq, wasOnPending)
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
	prevGroup, prevReq, wasOnPending := selectionAnchors(m)
	m.Ops = e.Ops
	m.LastErr = ""
	preserveSelection(&m, prevGroup, prevReq, wasOnPending)
	clampSelection(&m)
	// #192: advance the per-row animation tick. Only fires when the
	// tick is not paused — a paused pane should not have spinners
	// continuing to rotate (jarring) while the rest of the pane is
	// frozen.
	m.TickCount++

	// #180: time out a lingering info status. LastErr clears above on
	// every successful tick; LastInfo used to persist until the next
	// action, leaving e.g. "generalized → allow GET …" on screen for
	// minutes. Age the current message and clear it after the timeout;
	// a changed message resets the age so each new line gets its full
	// dwell.
	if m.LastInfo != m.statusInfoSeen {
		m.statusInfoSeen = m.LastInfo
		m.statusInfoAge = 0
	} else if m.LastInfo != "" {
		m.statusInfoAge++
		if m.statusInfoAge >= statusInfoTimeoutTicks {
			m.LastInfo = ""
			m.statusInfoSeen = ""
			m.statusInfoAge = 0
		}
	}

	// #156: idle-snap. Increment LastInputTicks; when it crosses the
	// threshold AND a pending row exists AND the cursor isn't
	// already on a pending row, snap to the bottommost row (= newest
	// pending) and reset the counter so the snap doesn't keep firing
	// every subsequent tick. Cursor-already-on-pending is the
	// "don't move the cursor on the pending stack" invariant — the
	// operator is already on actionable work; don't yank them.
	m.LastInputTicks++
	if m.LastInputTicks >= idleSnapTicks {
		displayed := DisplayedOps(m)
		if len(displayed) > 0 {
			last := len(displayed) - 1
			onPending := m.Selected >= 0 && m.Selected < len(displayed) &&
				displayed[m.Selected].Status == opstream.StatusPending
			if !onPending && displayed[last].Status == opstream.StatusPending {
				m.Selected = last
				m.LastInputTicks = 0
			}
		}
	}

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

// selectionAnchors returns three stable identifiers for the operator's
// currently-selected row, captured BEFORE m.Ops / m.Holds is replaced
// by a tick so the post-tick preserve-selection step can re-locate
// the same logical row (closes #89 part 2, #119, #191):
//
//   - group: the row's GroupKey — the folded group's identity, stable
//     across a representative flip when a newer op joins the group.
//   - req: the representative op's request_id (or `hold:<holdID>`) —
//     a fallback for when the group itself changed shape.
//   - wasOnPending: true when the selected row is in the non-resolved
//     region (pending / signaled / checking). Lets preserveSelection
//     keep the cursor in the pending region across a status flip —
//     the #191 invariant that "only Up arrow moves the cursor off
//     pending."
//
// group and req are "" and wasOnPending is false when no row is
// selected.
func selectionAnchors(m Model) (group, req string, wasOnPending bool) {
	displayed := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(displayed) {
		return "", "", false
	}
	sel := displayed[m.Selected]
	req = sel.RequestID
	if req == "" {
		req = "hold:" + sel.HoldID
	}
	return sel.GroupKey, req, !opIsResolved(sel.Status)
}

// preserveSelection keeps the operator's selection on the same logical
// row across refresh ticks (closes #39, #52, #89, #119, #191). The
// caller passes the anchors captured by selectionAnchors BEFORE the
// new m.Ops/m.Holds was written.
//
// It matches by GroupKey first: a folded group keeps its identity even
// when a newer op joins and flips the representative — the case #119's
// wider grouping key makes common (a burst of similar URLs would
// otherwise re-pick the representative every tick and drop the
// cursor). It then falls back to the representative's request id,
// which covers a row whose group key changed shape between ticks (e.g.
// a pending op resolving). If neither matches, Selected resets to -1
// and clampSelection moves it onto the head of the list afterwards.
//
// Section affinity (#191): when wasOnPending is true, a match in the
// resolved region is rejected — the operator was working through
// pending requests and the cursor must not follow the row it was on
// into resolved just because that row's status flipped. The fall-
// through routes the cursor to the bottommost pending row, the same
// landing site the #156 idle-snap uses. When no pending row remains,
// the invariant is vacuous and the cursor falls through to whatever
// clampSelection picks afterwards.
func preserveSelection(m *Model, prevGroup, prevReq string, wasOnPending bool) {
	if prevGroup == "" && prevReq == "" {
		return
	}
	rebuilt := DisplayedOps(*m)
	m.Selected = -1
	acceptSection := func(o DisplayedOp) bool {
		if !wasOnPending {
			return true
		}
		return !opIsResolved(o.Status)
	}
	if prevGroup != "" {
		for i, o := range rebuilt {
			if o.GroupKey == prevGroup && acceptSection(o) {
				m.Selected = i
				return
			}
		}
	}
	if prevReq != "" {
		for i, o := range rebuilt {
			key := o.RequestID
			if key == "" {
				key = "hold:" + o.HoldID
			}
			if key == prevReq && acceptSection(o) {
				m.Selected = i
				return
			}
		}
	}
	// No same-anchor match in the acceptable region. If the cursor was
	// on pending and any pending row remains, snap to the bottommost
	// pending row (matches the #156 idle-snap target — newest pending,
	// the operator's next actionable work). When no pending row
	// remains, leave Selected at -1 for clampSelection to land on
	// row 0.
	if wasOnPending {
		for i := len(rebuilt) - 1; i >= 0; i-- {
			if !opIsResolved(rebuilt[i].Status) {
				m.Selected = i
				return
			}
		}
	}
}

func applyKey(m Model, e KeyEvent) (Model, Cmd) {
	// #156: any key event resets the idle counter so the cursor
	// idle-snap (in applyOpsTick) doesn't fire while the operator
	// is actively driving the UI. Reset first thing — the rest of
	// this function may early-return.
	m.LastInputTicks = 0
	// Global keys — fire regardless of focus.
	if e.Key == KeyCtrlC {
		m.Quit = true
		return m, CmdQuit{}
	}
	// Ctrl-L is a hard repaint (#115). Global, state-preserving:
	// no focus change, no panel toggle, no console emission.
	if e.Key == KeyCtrlL {
		return m, CmdRepaint{}
	}
	// Generalization card is modal while shown (#170): a/d/tab/esc act
	// on the card so they cannot leak to approve/deny or focus toggle.
	// Placed after Ctrl-C/Ctrl-L so quit and repaint still work.
	if m.GenCard != nil {
		return applyKeyGenCard(m, e)
	}
	// Pre-#168 the 1/2/3 generalize-offer prompt was intercepted
	// here. The prompt was removed in #168 in favor of the
	// daemon-owned quiet-moment suggestion lifecycle, so the
	// keystroke flows straight to the normal dispatch.
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
	// Pane-specific dispatch via a map (closes #98 part 1).
	// Adding a new bottom panel is a one-line registration here
	// instead of another conditional in this chain.
	if m.Focused == PaneConsole {
		if h, ok := bottomPanelKeyHandlers[m.BottomPanel]; ok {
			return h(m, e)
		}
		return applyKeyConsole(m, e)
	}
	return applyKeyApprovals(m, e)
}

// bottomPanelKeyHandlers dispatches keystrokes to the per-panel
// reducer when the console pane is focused. Read-only panels
// (BottomPanelInfo) fall through to the default applyKeyConsole
// handler — there's nothing pane-specific to react to. Closes #98
// part 1 (replaces the prior if/else-if chain in applyKey).
var bottomPanelKeyHandlers = map[BottomPanel]func(Model, KeyEvent) (Model, Cmd){
	BottomPanelURLs: applyKeyURLs,
	BottomPanelLLM:  applyKeyLLM,
}

// applyMetaPanelDigitKey handles the '0'-'4' panel-switch keys
// shared between approvals focus and any panel handler that wants
// to forward them (#98 part 4: meta-key passthrough). Returns
// handled=true when the key was a digit '0'-'4' and the model has
// been mutated; false otherwise. Centralizes the prior switch
// statement in applyKeyApprovals so the URLs and LLM panels can
// pass digits through to the same logic.
func applyMetaPanelDigitKey(m Model, e KeyEvent) (Model, Cmd, bool) {
	if e.Rune < '0' || e.Rune > '4' {
		return m, CmdNone{}, false
	}
	// Any explicit panel choice cancels a URLs-pending-return and
	// releases the nav-pause (#86, #89).
	m.URLsPendingReturn = false
	m.OpsPausedTicks = 0
	switch e.Rune {
	case '0':
		m.BottomPanelOpen = false
		m.Focused = PaneApprovals
		return m, CmdNone{}, true
	case '1':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelConsole {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}, true
		}
		m.BottomPanel = BottomPanelConsole
		m.BottomPanelOpen = true
		m.Focused = PaneConsole
		return m, CmdNone{}, true
	case '2':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelInfo {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}, true
		}
		m.BottomPanel = BottomPanelInfo
		m.BottomPanelOpen = true
		// Info is a read-only reflection of the approvals selection; it
		// has no text input and must not hold PaneConsole focus. When
		// opened from a console-focused pane (URLs/LLM) without this,
		// dispatch falls through to applyKeyConsole (BottomPanelInfo has
		// no handler) which swallows digit keys into the hidden console
		// input — the #171 "0/4 do nothing, only esc closes" trap.
		m.Focused = PaneApprovals
		return m, CmdNone{}, true
	case '3':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelLLM {
			m.BottomPanelOpen = false
			m.DigestExpanded = false
			m.Focused = PaneApprovals
			return m, CmdNone{}, true
		}
		m.BottomPanel = BottomPanelLLM
		m.BottomPanelOpen = true
		m.Focused = PaneConsole
		if m.DigestSelected == "" && len(m.Digests) > 0 {
			m.DigestSelected = m.Digests[len(m.Digests)-1].RequestID
		}
		m.DigestExpanded = true
		return m, CmdDigestRefresh{}, true
	case '4':
		if m.BottomPanelOpen && m.BottomPanel == BottomPanelURLs {
			m.BottomPanelOpen = false
			m.Focused = PaneApprovals
			return m, CmdNone{}, true
		}
		m.BottomPanel = BottomPanelURLs
		m.BottomPanelOpen = true
		m.Focused = PaneConsole
		return m, CmdURLsRefresh{}, true
	}
	return m, CmdNone{}, false
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
	// (Per-panel KeyEsc handler removed — central applyKey handles
	// Esc unconditionally before this is reached, closing the panel
	// and resetting DigestExpanded. The prior two-stage collapse-
	// first / close-second behavior is no longer accessible; the
	// production contract is "Esc closes the LLM panel entirely; Enter
	// is collapse-but-keep-open" as pinned by
	// TestApplyKey_EscClosesLLMPanelEvenWhenExpanded. #105 cleanup.)
	if e.Rune == 'q' {
		// `q` defocuses (does not quit the TUI); quitting still
		// works from approvals focus.
		m.DigestExpanded = false
		m.Focused = PaneApprovals
		return m, CmdNone{}
	}
	// Meta-key passthrough (#98 part 4): '0'-'4' switch panels even
	// from the LLM handler so the operator can hop between panels
	// without first defocusing back to approvals. The shared helper
	// also handles the LLM-specific cleanup (DigestExpanded reset)
	// when '3' toggles the LLM panel closed.
	if mNew, cmd, handled := applyMetaPanelDigitKey(m, e); handled {
		return mNew, cmd
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
	// #196: Home jumps to the first digest (index 0 = newest, per
	// the existing j/k semantics where Up moves toward newer);
	// End jumps to the last (oldest) digest.
	if e.Key == KeyHome {
		if len(m.Digests) > 0 {
			if d, ok := digestAtDisplayIndex(m, 0); ok {
				m.DigestSelected = d.RequestID
				m.DigestExpanded = true
			}
		}
		return m, CmdNone{}
	}
	if e.Key == KeyEnd {
		if len(m.Digests) > 0 {
			if d, ok := digestAtDisplayIndex(m, len(m.Digests)-1); ok {
				m.DigestSelected = d.RequestID
				m.DigestExpanded = true
			}
		}
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
	// (Per-panel KeyEsc handler removed — central applyKey at the
	// top of dispatch handles Esc before this is reached. #105
	// cleanup.)
	// Meta-key passthrough (#98 part 4): '0'-'4' switch panels even
	// from the URLs handler, so an operator browsing URLs can hop to
	// the LLM panel without first defocusing back to approvals.
	if mNew, cmd, handled := applyMetaPanelDigitKey(m, e); handled {
		return mNew, cmd
	}
	combinedLen := len(m.AllowList) + len(m.DenyList)
	// Shift-Up/Down build a contiguous multi-selection (#170): seed the
	// anchor from the current cursor on the first shift-move, then move
	// the cursor; the selected set is the inclusive [anchor,cursor]
	// range that `g` consumes.
	if e.Key == KeyShiftUp {
		if m.URLsAnchor < 0 {
			m.URLsAnchor = m.URLsSelected
		}
		if m.URLsSelected > 0 {
			m.URLsSelected--
		}
		return m, CmdNone{}
	}
	if e.Key == KeyShiftDown {
		if m.URLsAnchor < 0 {
			m.URLsAnchor = m.URLsSelected
		}
		if m.URLsSelected < combinedLen-1 {
			m.URLsSelected++
		}
		return m, CmdNone{}
	}
	if e.Key == KeyUp || e.Rune == 'k' {
		m.URLsAnchor = -1
		if m.URLsSelected > 0 {
			m.URLsSelected--
		}
		return m, CmdNone{}
	}
	if e.Key == KeyDown || e.Rune == 'j' {
		m.URLsAnchor = -1
		if m.URLsSelected < combinedLen-1 {
			m.URLsSelected++
		}
		return m, CmdNone{}
	}
	// #196: Home/End jump to first / last entry of the URLs list.
	if e.Key == KeyHome {
		m.URLsAnchor = -1
		if combinedLen > 0 {
			m.URLsSelected = 0
		}
		return m, CmdNone{}
	}
	if e.Key == KeyEnd {
		m.URLsAnchor = -1
		if combinedLen > 0 {
			m.URLsSelected = combinedLen - 1
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
	// On-demand suggest (#174): ask the daemon to scan the lists for a
	// generalization now, rather than waiting for a quiet moment. The
	// result surfaces in the same suggestion card.
	if e.Rune == 's' {
		m.LastErr = ""
		m.LastInfo = "scanning for generalizations…"
		return m, CmdSuggestNow{}
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

// urlsGeneralize builds the generalization card for the URLs pane (#170).
// With a multi-selection (Shift-Up/Down range of ≥2 entries) it runs the
// deterministic detector over the selected subset; otherwise it
// axis-generalizes the single cursor entry. Either way the resulting
// candidates populate m.GenCard, which the operations pane renders and
// which a/d/tab then drive. No candidate → an explanatory LastErr.
func urlsGeneralize(m Model) (Model, Cmd) {
	if !m.URLsLocal {
		m.LastErr = "allow/deny editing runs on the proxy host"
		return m, CmdNone{}
	}
	combined := append(append([]string(nil), m.AllowList...), m.DenyList...)
	if len(combined) == 0 {
		m.LastErr = "no URLs to generalize"
		return m, CmdNone{}
	}
	lo, hi := m.URLsSelected, m.URLsSelected
	if m.URLsAnchor >= 0 {
		lo, hi = m.URLsAnchor, m.URLsSelected
		if lo > hi {
			lo, hi = hi, lo
		}
	}
	if lo < 0 {
		m.URLsAnchor = -1
		m.LastErr = "no URL selected to generalize"
		return m, CmdNone{}
	}
	var cands []generalize.Candidate
	var srcDesc string
	if hi > lo {
		// Multi-select: split the range into allow/deny subsets (the
		// detector never mixes lists) and run DetectAll over them.
		var allowSel, denySel []string
		for i := lo; i <= hi && i < len(combined); i++ {
			if i < len(m.AllowList) {
				allowSel = append(allowSel, combined[i])
			} else {
				denySel = append(denySel, combined[i])
			}
		}
		cands = generalize.DetectAll(allowSel, denySel)
		srcDesc = fmt.Sprintf("%d selected entries", hi-lo+1)
	} else {
		entry := combined[lo]
		side := "allow"
		if lo >= len(m.AllowList) {
			side = "deny"
		}
		cands = generalize.GeneralizeOne(entry, side)
		srcDesc = "1 entry: " + entry
	}
	m.URLsAnchor = -1
	if len(cands) == 0 {
		if hi > lo {
			m.LastErr = "no generalization across the selected entries"
		} else {
			m.LastErr = "no generalization for " + combined[lo]
		}
		return m, CmdNone{}
	}
	m.GenCard = &GeneralizeCard{Candidates: cands, AxisIndex: 0, SourceDesc: srcDesc}
	m.LastErr = ""
	return m, CmdNone{}
}

// applyKeyGenCard handles keys while the generalization card is up
// (#170). The card is modal: accept writes the current candidate's
// pattern through the same configwrite path a typed `allow <pat>`
// uses (mirroring daemon Manager.Accept — add the pattern, keep the
// sources); decline/esc dismiss; tab rotates the axis. Every other
// key is swallowed so a/d/tab cannot reach approve/deny or focus.
func applyKeyGenCard(m Model, e KeyEvent) (Model, Cmd) {
	switch {
	case e.Rune == 'a' || e.Key == KeyEnter:
		// Enter accepts the shown candidate, same as 'a' (#178).
		c := m.GenCard.Current()
		m.GenCard = nil
		m.LastErr = ""
		m.LastInfo = "generalized → " + c.List + " " + c.SuggestedPattern
		// Snap back to the URLs list and refresh after the write so the
		// operator sees the new pattern and the pruned specifics (#86
		// return-path). Accept removes the source entries the pattern
		// replaces and adds the pattern, atomically (#173).
		m.URLsPendingReturn = true
		return m, CmdGeneralizeAccept{List: c.List, Pattern: c.SuggestedPattern, Sources: c.SourceEntries}
	case e.Rune == 'd' || e.Key == KeyEsc:
		m.GenCard = nil
		return m, CmdNone{}
	case e.Key == KeyTab || e.Key == KeyShiftTab:
		card := *m.GenCard
		card.AxisIndex = (card.AxisIndex + 1) % len(card.Candidates)
		m.GenCard = &card
		return m, CmdNone{}
	}
	return m, CmdNone{}
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
	// Suspend to the host shell (#176). `z` (not Ctrl-Z, which the URLs
	// pane uses for undo) backgrounds the process via SIGTSTP; `fg`
	// resumes it. Handled here in the approvals pane so it never steals
	// a literal 'z' the operator is typing into the console.
	if e.Rune == 'z' {
		return m, CmdSuspend{}
	}
	// Daemon suggestion accept/decline (#172). The suggestion is
	// ambient (it appears at quiet moments), so it uses shift+a/shift+d
	// — uppercase 'A'/'D' runes — rather than the modal a/d of the
	// manual generalize card, to avoid stealing approve/deny. Gated on
	// a live suggestion so the keys are inert otherwise.
	if m.Suggestion != nil {
		if e.Rune == 'A' {
			return m, CmdSuggestionAccept{ID: m.Suggestion.ID}
		}
		if e.Rune == 'D' {
			return m, CmdSuggestionDecline{ID: m.Suggestion.ID}
		}
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
	// #196: Home/End jump to first / last row of the operations list.
	if e.Key == KeyHome {
		if len(displayed) > 0 {
			m.Selected = 0
		}
		m.OpsPausedTicks = opsPauseTicks
		return m, CmdNone{}
	}
	if e.Key == KeyEnd {
		if len(displayed) > 0 {
			m.Selected = len(displayed) - 1
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
	if mNew, cmd, handled := applyMetaPanelDigitKey(m, e); handled {
		return mNew, cmd
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
				return m, CmdApprove{ID: op.HoldID, Method: op.Method, URL: op.URL}
			}
			m.LastInfo = "denying " + target + "…"
			return m, CmdDeny{ID: op.HoldID, Method: op.Method, URL: op.URL}
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
		specific := allowDenyPattern(op.Method, op.URL)
		m.LastInfo = verb + "ing " + specific + "…"
		// Pre-#168 the approve branch queued a 1/2/3 generalize-offer
		// prompt here; #168 removed that surface in favor of the
		// quiet-moment suggestion lifecycle owned by the daemon. The
		// pattern persists and the next quiet moment will run the
		// detector across the (now larger) list.
		return m, CmdConsoleExec{Line: verb + " " + specific}
	}
	return m, CmdNone{}
}

// allowDenyPattern builds the list pattern for a request row: the
// uppercased method (or "*" when absent) followed by the URL, matching
// the shape the console's `allow`/`deny` commands expect. Shared by
// the retroactive add-to-list keypress (#60/#85) and the approve/deny
// hold-not-found fallback (#184) so the two never drift.
func allowDenyPattern(method, url string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "*"
	}
	return m + " " + url
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
	// (Per-pane KeyEsc case removed — central applyKey handles Esc
	// before this dispatch is reached. Closing the panel from the
	// console focus is the correct behavior; the prior "back out
	// to approvals while keeping panel open" behavior was already
	// dead code. #105 cleanup.)
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
		// #184: a hold can be resolved out from under the operator
		// (timeout, advisor, double-press) while its row still shows
		// pending. The hold is a transient pointer — the operator's
		// intent to allow/deny the URL still stands. When we have the
		// URL, fall back to the same allow/deny-list write the
		// retroactive add-to-list keypress uses (#60), so the action
		// succeeds instead of dead-ending on "hold not found".
		if errors.Is(e.Err, controlclient.ErrHoldNotFound) && e.URL != "" {
			verb := "allow"
			if e.Action == "deny" {
				verb = "deny"
			}
			specific := allowDenyPattern(e.Method, e.URL)
			m.LastInfo = verb + "ing " + specific + " (hold already resolved)…"
			m.LastErr = ""
			return m, CmdConsoleExec{Line: verb + " " + specific}
		}
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
	// GroupKey is the stable identity of this displayed row, used to
	// keep the operator's selection anchored across refresh ticks even
	// as a folded group's representative op changes (#119). For a
	// folded resolved group it encodes (method, host, dir, status);
	// for a never-folded row (pending / signaled / checking) it
	// encodes the op's own request or hold id.
	GroupKey string
}

// DisplayedOps returns the unified list rendered in the upper pane:
// the ops ring (newest first) merged with any pending holds that the
// ring no longer carries (evicted under burst pressure). Holds that
// are NOT in the ring become synthetic ops with status "pending" so
// the operator never silently loses an actionable hold.
//
// Resolved ops are then grouped by (Method, Host, Directory, Status):
// requests to the same host and the same path directory that share a
// method and a final status collapse into one row whose Count records
// the repetition and whose representative is the newest op by
// UpdatedAt (closes #119, generalizing #63's identical-URL fold).
//
// Not-yet-resolved ops (pending, signaled, checking) are exempt from
// folding: each stays its own row so the a/d approve/deny keys always
// target one unambiguous request.
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

	type key struct{ method, host, dir, status string }
	indexOf := map[key]int{}
	out := make([]DisplayedOp, 0, len(flat))
	for _, o := range flat {
		if !opIsResolved(o.Status) {
			// Held / signaled / pre-decision ops never fold — each
			// stays an individually actionable row (#119).
			anchor := "o\x00" + o.RequestID
			if o.RequestID == "" {
				anchor = "h\x00" + o.HoldID
			}
			out = append(out, DisplayedOp{Op: o, Count: 1, GroupKey: anchor})
			continue
		}
		host, dir := opGroupHostDir(o.URL)
		k := key{o.Method, host, dir, o.Status}
		if i, ok := indexOf[k]; ok {
			out[i].Count++
			// Most-recent representative wins. Assigning .Op replaces
			// only the embedded op; Count and GroupKey are siblings
			// and stay put — the row's identity is the group, not the
			// representative.
			if o.UpdatedAt.After(out[i].UpdatedAt) {
				out[i].Op = o
			}
			continue
		}
		indexOf[k] = len(out)
		out = append(out, DisplayedOp{
			Op:       o,
			Count:    1,
			GroupKey: "g\x00" + o.Method + "\x00" + host + "\x00" + dir + "\x00" + o.Status,
		})
	}
	// #156: partition into [resolved | pending] so the operator's
	// eye lands at the bottom of the pane on a pending row. Within
	// pending, sort by StartedAt ascending — oldest at the top of
	// the pending region, newest at the very bottom. Resolved
	// ordering is preserved (newest-UpdatedAt-first per the ops
	// ring's iteration order). On idle the cursor snaps to the
	// last row in the slice, which is the newest pending — see
	// applyOpsTick.
	resolved := out[:0:0]
	var pending []DisplayedOp
	for _, o := range out {
		if opIsResolved(o.Status) {
			resolved = append(resolved, o)
		} else {
			pending = append(pending, o)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		return pending[i].StartedAt.Before(pending[j].StartedAt)
	})
	return append(resolved, pending...)
}

// opIsResolved reports whether an op has reached a final outcome and
// is therefore eligible for similarity folding in DisplayedOps. Held
// (pending), signaled, and pre-decision (checking) ops are NOT
// resolved: each must stay an individual row so it remains
// unambiguously actionable (#119).
func opIsResolved(status string) bool {
	switch status {
	case opstream.StatusPending, opstream.StatusSignaled, opstream.StatusChecking:
		return false
	default:
		return true
	}
}

// opsPendingSplit returns the index in a DisplayedOps slice where the
// non-resolved (pending / signaled / checking) tail begins.
// DisplayedOps orders [resolved... | pending...], so this equals the
// resolved count and len(displayed) when there is no pending tail. The
// pending tail renders as a card pinned to the bottom of the operations
// pane (#185); the resolved head scrolls independently above it. The
// operator's selection index spans the whole slice unchanged, so the
// cursor still crosses from resolved into pending by moving past the
// last resolved row, and leaves pending (back into resolved) by moving
// up off the first pending row.
func opsPendingSplit(displayed []DisplayedOp) int {
	for i := range displayed {
		if !opIsResolved(displayed[i].Status) {
			return i
		}
	}
	return len(displayed)
}

// opGroupHostDir splits an op URL into the (host, directory) pair used
// by DisplayedOps' similarity key (#119).
//
// For a scheme://host/path URL — intercepted ops and the synthetic
// pending ops built above — it returns the host and the directory:
// the path truncated to and including its last '/', so files in the
// same directory share a key. Query and fragment are ignored.
//
// CONNECT and TLS ops are recorded scheme-less, as a bare "host" or
// "host:port" with no path (see server.opURLForRequest). url.Parse
// yields no host for those, so they take the second branch: the whole
// string becomes the host and the directory is empty. They therefore
// fold by exact host:port — the right behavior, since a CONNECT tunnel
// has no path dimension to group on. A genuinely unparseable URL lands
// in the same branch and likewise folds only with a byte-identical
// sibling, which is the safe degradation.
func opGroupHostDir(rawURL string) (host, dir string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL, ""
	}
	p := u.Path
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return u.Host, p[:i+1]
	}
	return u.Host, "/"
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
