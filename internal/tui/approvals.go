package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/dandriscoll/trollbridge/internal/opstream"
	"golang.org/x/term"
)

// ControlClient is the small surface the TUI needs from the daemon.
// Two implementations ship: NewInProcessClient for `trollbridge run`
// (TUI and daemon share a process; calls underlying state directly)
// and NewHTTPClient for `trollbridge attach` (separate process; talks
// to the mTLS control plane).
//
// RecentOps drives the upper-pane rendering (closes #52); ListHolds
// is still here because CLI subcommands (`trollbridge approve`,
// `trollbridge attach`) plus the upper-pane backstop for ops evicted
// under burst pressure both need it.
type ControlClient interface {
	ListHolds() ([]approvals.Snapshot, error)
	RecentOps() ([]opstream.Op, error)
	Approve(id string) error
	Deny(id, reason string) error
	// RecentLLMDigests returns recent advisor.Classify outcomes for
	// the LLM bottom panel (closes #66). In-process clients delegate
	// to advisor.Service.Digests(); HTTP clients call the control-
	// plane /v1/llm-digests endpoint (closes #99 part 2).
	RecentLLMDigests() ([]advisor.Digest, error)
	// RecentURLs returns the daemon's current allow/deny lists for
	// the URLs bottom panel. In-process clients reach the server's
	// list state directly; HTTP clients call /v1/lists (closes #99
	// part 1). ok=false signals the daemon does not expose the lists
	// (returned for null providers); the renderer then shows the
	// attach-mode hint instead of an empty list.
	RecentURLs() (allow, deny []string, ok bool, err error)
}

type httpClient struct{ cfg *config.Config }

func (c *httpClient) ListHolds() ([]approvals.Snapshot, error) {
	body, err := controlclient.Get(c.cfg, "/v1/holds")
	if err != nil {
		return nil, err
	}
	var out []approvals.Snapshot
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode holds: %w", err)
	}
	return out, nil
}

func (c *httpClient) RecentOps() ([]opstream.Op, error) {
	body, err := controlclient.Get(c.cfg, "/v1/ops")
	if err != nil {
		return nil, err
	}
	var out []opstream.Op
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode ops: %w", err)
	}
	return out, nil
}

func (c *httpClient) Approve(id string) error {
	_, err := controlclient.HoldAction(c.cfg, id, "approve", "once", "")
	return err
}

func (c *httpClient) Deny(id, reason string) error {
	_, err := controlclient.HoldAction(c.cfg, id, "deny", "", reason)
	return err
}

func (c *httpClient) RecentLLMDigests() ([]advisor.Digest, error) {
	body, err := controlclient.Get(c.cfg, "/v1/llm-digests")
	if err != nil {
		return nil, err
	}
	var out []advisor.Digest
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode llm-digests: %w", err)
	}
	return out, nil
}

func (c *httpClient) RecentURLs() (allow, deny []string, ok bool, err error) {
	body, gerr := controlclient.Get(c.cfg, "/v1/lists")
	if gerr != nil {
		return nil, nil, false, gerr
	}
	var resp struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	if uerr := json.Unmarshal(body, &resp); uerr != nil {
		return nil, nil, false, fmt.Errorf("decode lists: %w", uerr)
	}
	return resp.Allow, resp.Deny, true, nil
}

// NewHTTPClient returns a ControlClient that talks to the daemon's
// mTLS control plane. Used by `trollbridge attach` (separate process).
func NewHTTPClient(cfg *config.Config) ControlClient {
	return &httpClient{cfg: cfg}
}

type inProcessClient struct {
	q   *approvals.Queue
	ops *opstream.Ring
	// adv is the advisor service whose Digests() ring backs the
	// LLM bottom panel (closes #66). May be nil if no advisor wired.
	adv *advisor.Service
}

func (c *inProcessClient) ListHolds() ([]approvals.Snapshot, error) {
	if c.q == nil {
		return nil, errors.New("approvals queue not initialized")
	}
	return c.q.Pending(), nil
}

func (c *inProcessClient) RecentOps() ([]opstream.Op, error) {
	if c.ops == nil {
		return nil, nil
	}
	return c.ops.Snapshot(), nil
}

func (c *inProcessClient) Approve(id string) error {
	if c.q == nil {
		return errors.New("approvals queue not initialized")
	}
	if !c.q.Approve(id, "once", "tui") {
		return fmt.Errorf("hold not found: %s", id)
	}
	return nil
}

func (c *inProcessClient) Deny(id, reason string) error {
	if c.q == nil {
		return errors.New("approvals queue not initialized")
	}
	if !c.q.Deny(id, reason, "tui") {
		return fmt.Errorf("hold not found: %s", id)
	}
	return nil
}

func (c *inProcessClient) RecentLLMDigests() ([]advisor.Digest, error) {
	if c.adv == nil {
		return nil, nil
	}
	return c.adv.Digests().Snapshot(), nil
}

// RecentURLs on the in-process client returns ok=false because the
// `trollbridge run` flow loads lists from the on-disk config file
// directly (the existing CmdURLsRefresh path); the in-process URL
// surface is not exposed via the client interface to avoid a second
// source of truth. The renderer falls back to the file-loading code
// path. The HTTP client is the only RecentURLs consumer that
// actually returns data (closes #99 part 1).
func (c *inProcessClient) RecentURLs() ([]string, []string, bool, error) {
	return nil, nil, false, nil
}

// NewInProcessClient returns a ControlClient that calls the daemon's
// approvals queue and ops ring directly. Use this when the operator
// UI is embedded in the daemon (e.g. `trollbridge run`): it removes
// the mTLS hop and the controller-client.{crt,key} requirement that
// otherwise wedges the approvals pane silently when the cert is
// absent. ops may be nil; the upper pane then degrades to a holds-
// only view.
func NewInProcessClient(q *approvals.Queue, ops *opstream.Ring) ControlClient {
	return &inProcessClient{q: q, ops: ops}
}

// NewInProcessClientWithAdvisor is the variant that also wires the
// advisor service for the LLM bottom panel (closes #66). adv may be
// nil — the LLM panel then renders empty.
func NewInProcessClientWithAdvisor(q *approvals.Queue, ops *opstream.Ring, adv *advisor.Service) ControlClient {
	return &inProcessClient{q: q, ops: ops, adv: adv}
}

// RunOperator drives the unified two-pane operator UI. The caller
// chooses the ControlClient: NewInProcessClient(queue) for the
// embedded path (`trollbridge run`), NewHTTPClient(cfg) for the
// remote path (`trollbridge attach`).
//
// requestShutdown, when non-nil, is invoked when the operator exits
// the TUI via Ctrl-C / `q` / `quit` — before RunOperator returns.
// In `trollbridge run` and `trollbridge quickstart` the caller passes
// the parent context's cancel function so the embedded operator UI
// can take down the proxy on a single Ctrl-C; without it the first
// Ctrl-C is consumed by the TUI's raw-mode stdin (terminal does not
// emit SIGINT) and the daemon stays blocked in ListenAndServe until
// a second press, after the TUI has restored cooked mode (closes #48).
// `trollbridge attach` passes nil — its TUI is a remote client, not
// the daemon.
func RunOperator(ctx context.Context, client ControlClient, in, out *os.File, backend *console.Backend, welcome string, requestShutdown func(), opts Options) (err error) {
	return runWithClient(ctx, in, out, client, backend, welcome, requestShutdown, opts)
}

// Options bundles operator-UI preferences that span the TUI's
// lifetime. Callers should compose with DefaultOptions() and adjust
// only the fields they want to override.
type Options struct {
	// ChimeEnabled, when true, lets the TUI emit a single BEL on
	// every tick where the pending count rises. The operator can
	// toggle this at runtime by pressing `b`. False pre-mutes;
	// `b` still unmutes (#72).
	ChimeEnabled bool
}

// DefaultOptions returns the TUI's default Options: chime on.
func DefaultOptions() Options {
	return Options{ChimeEnabled: true}
}

func runWithClient(ctx context.Context, in, out *os.File, client ControlClient, backend *console.Backend, welcome string, requestShutdown func(), opts Options) (err error) {
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return errors.New("trollbridge ui: stdin/stdout is not a terminal")
	}
	// Windows: opt into ANSI VT processing before entering raw mode
	// so failures are reported on the original screen rather than a
	// half-broken alt-screen. Unix: no-op (closes #61).
	if err := enableConsoleVT(); err != nil {
		return err
	}
	oldState, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return fmt.Errorf("trollbridge ui: enter raw mode: %w", err)
	}
	defer func() {
		// Always restore the cooked terminal state. Hide-cursor /
		// alt-screen state is reset before restore so the operator's
		// shell looks normal afterwards.
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), oldState)
		if r := recover(); r != nil {
			err = fmt.Errorf("trollbridge ui: panic: %v", r)
		}
	}()
	// Enter alternate screen + hide cursor so the host shell's
	// scrollback is preserved.
	fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")

	cols, rows, _ := term.GetSize(int(out.Fd()))
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	return runLoop(ctx, client, backend, in, out, out, cols, rows, welcome, requestShutdown, opts)
}

// runLoop is the testable inner loop. resize may be nil in tests.
// requestShutdown, when non-nil, is invoked when the loop exits via
// operator-initiated quit (CmdQuit) — see RunOperator for rationale.
// It is NOT invoked when the loop exits because ctx is already done
// (the parent is already shutting down for another reason).
func runLoop(ctx context.Context, client ControlClient, backend *console.Backend, in io.Reader, out io.Writer, resize *os.File, cols, rows int, welcome string, requestShutdown func(), opts Options) error {
	model := Model{
		Selected: -1,
		Cols:     cols,
		Rows:     rows,
		Focused:  PaneApprovals,
		Console:  ConsoleModel{Prompt: "trollbridge> "},
		Alerts:   AlertsState{ChimeEnabled: opts.ChimeEnabled},
	}
	if welcome != "" {
		for _, line := range splitLines(welcome) {
			model.Console = appendScrollback(model.Console, line)
		}
	} else {
		model.Console = appendScrollback(model.Console, "type `help` for commands · Tab to switch panes")
	}

	events := make(chan Event, 32)
	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()

	consoleQueue := make(chan string, 8)
	go consoleWorker(loopCtx, backend, consoleQueue, events)

	go readKeys(loopCtx, in, events)
	go tickRefresh(loopCtx, client, events)
	if resize != nil {
		go watchResize(loopCtx, resize, events)
	}

	// First paint with empty list before the first tick lands.
	_ = render(out, model)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var ev Event
		select {
		case <-ctx.Done():
			return nil
		case ev = <-events:
		}

		var cmd Cmd
		model, cmd = Apply(model, ev)
		_ = render(out, model)

		if model.Quit {
			if requestShutdown != nil {
				requestShutdown()
			}
			return nil
		}

		switch c := cmd.(type) {
		case CmdQuit:
			if requestShutdown != nil {
				requestShutdown()
			}
			return nil
		case CmdRefresh:
			go func() {
				holds, err := client.ListHolds()
				select {
				case <-loopCtx.Done():
				case events <- TickResult{Holds: holds, Err: err}:
				}
			}()
			go func() {
				ops, err := client.RecentOps()
				select {
				case <-loopCtx.Done():
				case events <- OpsTickResult{Ops: ops, Err: err}:
				}
			}()
		case CmdApprove:
			id := c.ID
			go func() {
				err := client.Approve(id)
				select {
				case <-loopCtx.Done():
				case events <- ActionResult{ID: id, Action: "approve", Err: err}:
				}
			}()
		case CmdDeny:
			id := c.ID
			go func() {
				err := client.Deny(id, "operator denied")
				select {
				case <-loopCtx.Done():
				case events <- ActionResult{ID: id, Action: "deny", Err: err}:
				}
			}()
		case CmdDigestRefresh:
			go func() {
				ds, err := client.RecentLLMDigests()
				select {
				case <-loopCtx.Done():
				case events <- DigestTickResult{Digests: ds, Err: err}:
				}
			}()
		case CmdURLsRefresh:
			// Allow/deny lists live in trollbridge.yaml on the proxy
			// host. In LocalOnly (run) mode the operator is on that
			// host and backend.ConfigPath points at the live file;
			// in attach mode it's empty and we fall back to the
			// control-plane /v1/lists endpoint (#99 part 1) which
			// returns the daemon's live list state.
			cfgPath := ""
			if backend != nil {
				cfgPath = backend.ConfigPath
			}
			if cfgPath == "" {
				go func() {
					allow, deny, ok, err := client.RecentURLs()
					if err != nil {
						select {
						case <-loopCtx.Done():
						case events <- URLsTickResult{Local: false, Err: err}:
						}
						return
					}
					if !ok {
						// Daemon does not expose the lists (older
						// daemon, or in-process client which routes
						// the renderer through the file-load path
						// when ConfigPath is set). Render the
						// attach-mode hint as before.
						select {
						case <-loopCtx.Done():
						case events <- URLsTickResult{Local: false}:
						}
						return
					}
					select {
					case <-loopCtx.Done():
					case events <- URLsTickResult{
						Allow: filterListEntries(allow),
						Deny:  filterListEntries(deny),
						Local: false,
					}:
					}
				}()
				break
			}
			go func() {
				cfg, err := config.Load(cfgPath)
				if err != nil {
					select {
					case <-loopCtx.Done():
					case events <- URLsTickResult{Local: true, Err: err}:
					}
					return
				}
				select {
				case <-loopCtx.Done():
				case events <- URLsTickResult{
					Allow: filterListEntries(cfg.Lists.Allow),
					Deny:  filterListEntries(cfg.Lists.Deny),
					Local: true,
				}:
				}
			}()
		case CmdConsoleExec:
			select {
			case consoleQueue <- c.Line:
			default:
				// Worker is busy with a prior command; rather than
				// blocking the event loop (Ctrl-C must stay
				// responsive), drop the new command with a
				// scrollback hint.
				select {
				case <-loopCtx.Done():
				case events <- ConsoleExecResult{Line: c.Line, Output: "console busy: a prior command is still running\n"}:
				}
			}
		case CmdRingBell:
			// Single BEL byte; terminal emulators map this to beep,
			// flash, or a desktop notification per the operator's
			// own preferences. Errors are swallowed — we're writing
			// to the same `out` that the renderer already uses, so
			// any failure here is a downstream render-side problem
			// the next render will surface.
			_, _ = out.Write([]byte{0x07})
			_ = c
		}
	}
}

// consoleWorker serializes Backend.Execute calls so that two
// concurrent allow/deny writes cannot race the configwrite
// rename. It also recovers from backend panics so a broken
// callback (test/doctor wiring) cannot kill the goroutine.
func consoleWorker(ctx context.Context, backend *console.Backend, in <-chan string, events chan<- Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-in:
			if !ok {
				return
			}
			out, quit := safeExecute(backend, line)
			select {
			case <-ctx.Done():
				return
			case events <- ConsoleExecResult{Line: line, Output: out, Quit: quit}:
			}
		}
	}
}

func safeExecute(backend *console.Backend, line string) (output string, quit bool) {
	defer func() {
		if r := recover(); r != nil {
			output += fmt.Sprintf("panic: %v\n", r)
		}
	}()
	if backend == nil {
		return "", false
	}
	var buf bytes.Buffer
	quit = backend.Execute(&buf, line)
	return buf.String(), quit
}

// readKeys reads from the operator's stdin in raw mode, parses
// printable runes and a small set of ANSI escape sequences (arrow
// keys, Esc, Ctrl-C, Tab, Enter, Backspace, Ctrl-U) and forwards
// KeyEvents.
func readKeys(ctx context.Context, in io.Reader, events chan<- Event) {
	buf := make([]byte, 32)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := in.Read(buf)
		if err != nil {
			return
		}
		i := 0
		for i < n {
			b := buf[i]
			switch {
			case b == 0x03: // Ctrl-C
				sendKey(ctx, events, KeyEvent{Key: KeyCtrlC})
				i++
			case b == 0x09: // Tab
				sendKey(ctx, events, KeyEvent{Key: KeyTab})
				i++
			case b == 0x0d || b == 0x0a: // Enter / LF
				sendKey(ctx, events, KeyEvent{Key: KeyEnter})
				i++
			case b == 0x7f || b == 0x08: // DEL / BS
				sendKey(ctx, events, KeyEvent{Key: KeyBackspace})
				i++
			case b == 0x15: // Ctrl-U
				sendKey(ctx, events, KeyEvent{Key: KeyCtrlU})
				i++
			case b == 0x1a: // Ctrl-Z (undo, #86)
				sendKey(ctx, events, KeyEvent{Key: KeyCtrlZ})
				i++
			case b == 0x1b: // ESC, possibly start of a CSI sequence
				// 4-byte forms (`ESC [ <n> ~`) must be matched before the
				// 3-byte form, otherwise `ESC [ 3` would dispatch as a
				// 3-byte CSI and the trailing `~` would leak in as a
				// printable rune.
				if i+3 < n && buf[i+1] == '[' && buf[i+2] == '3' && buf[i+3] == '~' {
					sendKey(ctx, events, KeyEvent{Key: KeyDelete})
					i += 4
				} else if i+2 < n && buf[i+1] == '[' {
					switch buf[i+2] {
					case 'A':
						sendKey(ctx, events, KeyEvent{Key: KeyUp})
					case 'B':
						sendKey(ctx, events, KeyEvent{Key: KeyDown})
					case 'Z':
						// Shift-Tab as emitted by xterm/screen/tmux.
						sendKey(ctx, events, KeyEvent{Key: KeyShiftTab})
					}
					i += 3
				} else {
					sendKey(ctx, events, KeyEvent{Key: KeyEsc})
					i++
				}
			case b >= 0x20 && b < 0x7f: // printable ASCII
				sendKey(ctx, events, KeyEvent{Rune: rune(b)})
				i++
			default:
				i++
			}
		}
	}
}

func sendKey(ctx context.Context, events chan<- Event, ev KeyEvent) {
	select {
	case <-ctx.Done():
	case events <- ev:
	}
}

// tickRefresh schedules a refresh on first run and every 1.5s after.
// Two control-plane fetches per tick: holds (for the action source-
// of-truth) and ops (for the upper-pane render). They run as
// goroutines so a slow control plane on one endpoint does not stall
// the other.
func tickRefresh(ctx context.Context, client ControlClient, events chan<- Event) {
	emitHolds := func() {
		holds, err := client.ListHolds()
		select {
		case <-ctx.Done():
		case events <- TickResult{Holds: holds, Err: err}:
		}
	}
	emitOps := func() {
		ops, err := client.RecentOps()
		select {
		case <-ctx.Done():
		case events <- OpsTickResult{Ops: ops, Err: err}:
		}
	}
	emitHolds()
	emitOps()
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			go emitHolds()
			go emitOps()
		}
	}
}

// emitResize reads the current terminal size from out and pushes a
// ResizeEvent into events. Shared between the SIGWINCH-driven unix
// watcher and any other callers that need a one-shot resize push.
func emitResize(ctx context.Context, out *os.File, events chan<- Event) {
	cols, rows, _ := term.GetSize(int(out.Fd()))
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	select {
	case <-ctx.Done():
	case events <- ResizeEvent{Cols: cols, Rows: rows}:
	}
}

// render draws the current model to out using ANSI escapes. The
// terminal is split horizontally: the upper half hosts the approvals
// pane, the lower half hosts the console pane. Each pane carries its
// own top + bottom border with embedded help; there is no separate
// global hint row. On terminals narrower than borderMinThreshold the
// renderer falls back to the no-border layout (header rows + content).
func render(out io.Writer, m Model) error {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear

	if m.Cols < 1 {
		m.Cols = 80
	}
	if m.Rows < 6 {
		m.Rows = 24
	}

	bodyRows := m.Rows
	if bodyRows < 4 {
		bodyRows = 4
	}
	switch {
	case shouldRenderLLMModal(m, bodyRows):
		// Modal LLM detail view (closes #81): the expanded detail
		// for the selected digest does not fit inline, so it
		// replaces both panes in the body. Operator returns to the
		// panel with Esc.
		renderLLMModal(&b, m, bodyRows)
	case !m.BottomPanelOpen:
		// When the bottom panel is closed (the default), the
		// approvals pane fills the entire body — operator sees only
		// approvals until they press 1/2/3/4 to open something
		// below (closes #66).
		renderApprovalsPane(&b, m, bodyRows)
	default:
		topRows := bodyRows / 2
		if topRows < 3 {
			topRows = 3
		}
		bottomRows := bodyRows - topRows
		if bottomRows < 3 {
			bottomRows = 3
		}
		renderApprovalsPane(&b, m, topRows)
		renderBottomPane(&b, m, bottomRows)
	}

	// Strip the very last line terminator so the cursor settles on
	// the bottom row instead of one past it. With the trailing \n the
	// terminal scrolls up by one row at the end of every frame —
	// dropping the top border off-screen and producing the visible
	// "one line down, one line up" twitch in tmux at every refresh
	// tick (closes #50).
	frame := b.String()
	switch {
	case strings.HasSuffix(frame, "\r\n"):
		frame = frame[:len(frame)-2]
	case strings.HasSuffix(frame, "\n"):
		frame = frame[:len(frame)-1]
	}

	_, err := io.WriteString(out, frame)
	return err
}

func renderApprovalsPane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneApprovals
	if m.Cols < borderMinThreshold {
		renderApprovalsPaneNoBorder(b, m, rows)
		return
	}
	displayed := DisplayedOps(m)
	pending := 0
	for _, o := range displayed {
		if o.Status == opstream.StatusPending {
			pending++
		}
	}
	label := formatPaneLabel(formatOpsPaneLabelText(len(displayed), pending), focused)
	rightHint := ""
	if focused {
		// Panel-discovery hint when the bottom is hidden; Tab/hide cue
		// when a panel is showing. Both states keep the operator one
		// glance away from the next move (closes #66).
		if !m.BottomPanelOpen {
			rightHint = "[1]console [2]info [3]llm [4]urls"
		} else {
			rightHint = "[0]hide  " + formatTabHint(m.Focused)
		}
	}
	b.WriteString(topBorder(label, rightHint, m.Cols, focused))

	// Body: rows - 1 top border - 1 bottom border - 1 status row.
	bodyLines := rows - 3
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	used := 0
	if len(displayed) == 0 {
		b.WriteString(bodyLine(padRight(runeTrunc("  (no recent operations — waiting for traffic)", inner), inner), m.Cols, focused))
		used++
	} else {
		const methodW, countW, statusW, timeW = 7, 1, 11, 14
		urlW := inner - methodW - countW - statusW - timeW - 6 // 1 leading space + 4 column gaps + 1 trailing
		if urlW < 8 {
			urlW = 8
		}
		colHeader := fmt.Sprintf(" %-*s %-*s %s %-*s %s",
			methodW, "METHOD", urlW, "URL", " ", statusW, "STATUS", "TIME")
		b.WriteString(bodyLine(padRight(runeTrunc(colHeader, inner), inner), m.Cols, focused))
		used++
		now := time.Now()
		for i, o := range displayed {
			if used >= bodyLines {
				break
			}
			urlCell := runeTrunc(o.URL, urlW)
			urlCellPadded := padRight(urlCell, urlW)
			row := fmt.Sprintf(" %-*s %s %s %-*s %s",
				methodW, runeTrunc(o.Method, methodW),
				colorizeURLForRow(urlCellPadded, o.URL),
				brailleCounter(o.Count),
				statusW+8, runeTrunc(colorizeStatus(o.Status), statusW+8),
				formatOpTime(o.UpdatedAt, now),
			)
			row = padRightVisible(row, inner)
			if i == m.Selected {
				row = "\x1b[7m" + row + "\x1b[0m"
			}
			b.WriteString(bodyLine(row, m.Cols, focused))
			used++
		}
	}
	for used < bodyLines {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
		used++
	}

	// Status row (lives inside the border, above the bottom border).
	switch {
	case m.GeneralizeOffer != nil:
		// Post-approve prompt: name the specific entry just
		// written and the three broader options (#85). Cyan so
		// the operator notices a new-keystroke-expected state
		// without it reading like an error.
		text := formatGeneralizeOffer(*m.GeneralizeOffer)
		row := "\x1b[36m" + padRight(runeTrunc(text, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLine(row, m.Cols, focused))
	case m.LastErr != "":
		row := "\x1b[31m" + padRight(runeTrunc("error: "+m.LastErr, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLine(row, m.Cols, focused))
	case m.LastInfo != "":
		row := "\x1b[32m" + padRight(runeTrunc(m.LastInfo, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLine(row, m.Cols, focused))
	default:
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
	}

	// Bottom border carries the keybindings on the right.
	keys := "[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit"
	b.WriteString(bottomBorder("", keys, m.Cols, focused))
}

// formatGeneralizeOffer formats the post-approve "make this more
// general?" prompt shown in the approvals-pane status row
// (closes #85). The prompt names the specific entry that was just
// written, lists the three broader patterns, and reminds the
// operator that any other keystroke dismisses.
func formatGeneralizeOffer(o GeneralizeOffer) string {
	return fmt.Sprintf(
		"allowed %s %s — generalize? [1]all methods  [2]all URLs on host  [3]both  (any other key skips)",
		o.Method, o.URL)
}

// brailleCounter returns a single-rune Braille glyph whose dot count
// scales logarithmically with n: floor(log2(n)) bounded to [0, 8].
// n==1 returns " " — a single request needs no count indicator
// (closes #63).
func brailleCounter(n int) string {
	if n < 2 {
		return " "
	}
	dots := 0
	for v := n; v > 1; v >>= 1 {
		dots++
	}
	if dots > 8 {
		dots = 8
	}
	switch dots {
	case 1:
		return "⠁" // ⠁
	case 2:
		return "⠃" // ⠃
	case 3:
		return "⠇" // ⠇
	case 4:
		return "⠏" // ⠏
	case 5:
		return "⠟" // ⠟
	case 6:
		return "⠿" // ⠿
	case 7:
		return "⡿" // ⡿
	case 8:
		return "⣿" // ⣿
	}
	return " "
}

// formatOpTime renders an op's UpdatedAt in the compact form #67
// describes: HH:MM:SS for today (operator's local TZ); MM-DD HH:MM:SS
// for older. Year is always omitted.
func formatOpTime(t, now time.Time) string {
	local := t.Local()
	nowLocal := now.Local()
	if local.Year() == nowLocal.Year() && local.YearDay() == nowLocal.YearDay() {
		return local.Format("15:04:05")
	}
	return local.Format("01-02 15:04:05")
}

// colorizeURLForRow wraps cell in a brown 256-color escape when url
// is a plain-HTTP request (scheme http://), leaving other schemes
// uncolored. cell is the already-padded display string; passing it
// pre-padded keeps width accounting outside of this helper (closes
// #64).
func colorizeURLForRow(cell, url string) string {
	if strings.HasPrefix(url, "http://") {
		return "\x1b[38;5;94m" + cell + "\x1b[0m"
	}
	return cell
}

// formatOpsPaneLabelText builds the "trollbridge operations — …"
// label shown at the top of the approvals pane. When `pending > 0`,
// the pending segment gains a bell glyph and a bold+red ANSI wrap
// so the indicator is visible from across the room (closes #72).
// formatPaneLabel further wraps the result with the pane's focus
// styling.
func formatOpsPaneLabelText(total, pending int) string {
	if pending == 0 {
		return fmt.Sprintf("trollbridge operations — %d total · %d pending", total, pending)
	}
	// \x1b[1;31m = bold red. The bell-glyph prefix doubles as a
	// no-color affordance for terminals that strip ANSI.
	return fmt.Sprintf("trollbridge operations — %d total · \x1b[1;31m␇ %d pending\x1b[22;39m", total, pending)
}

// colorizeStatus wraps the status in a class color per #57's
// vocabulary: green for running/2xx, yellow for checking/pending/
// signaled, red for denied/error/4xx/5xx, cyan for 3xx. Unknown
// statuses pass through uncolored. The "denied" and "signaled"
// tokens replace the trollbridge-internal 470/471 wire codes per
// #71.
func colorizeStatus(status string) string {
	color := ""
	switch status {
	case opstream.StatusRunning:
		color = "\x1b[32m"
	case opstream.StatusChecking, opstream.StatusPending, opstream.StatusSignaled:
		color = "\x1b[33m"
	case opstream.StatusError, opstream.StatusDenied, opstream.StatusTLSFailed:
		color = "\x1b[31m"
	default:
		// HTTP status codes: 2xx green, 3xx cyan, 4xx/5xx red.
		switch {
		case len(status) == 3 && status[0] == '2':
			color = "\x1b[32m"
		case len(status) == 3 && status[0] == '3':
			color = "\x1b[36m"
		case len(status) == 3 && (status[0] == '4' || status[0] == '5'):
			color = "\x1b[31m"
		}
	}
	if color == "" {
		return status
	}
	return color + status + "\x1b[0m"
}

// padRightVisible pads s to width visible cells, ignoring ANSI escape
// sequences when computing length. The fast path (no escapes) defers
// to padRight.
func padRightVisible(s string, width int) string {
	if !strings.ContainsRune(s, '\x1b') {
		return padRight(s, width)
	}
	visible := visibleLen(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

// visibleLen returns the rune count of s with CSI escape sequences
// (ESC[ ... letter) excluded.
func visibleLen(s string) int {
	n := 0
	in := false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' || r == 'K' || r == 'J' || r == 'H' {
				in = false
			}
			continue
		}
		n++
	}
	return n
}

// renderApprovalsPaneNoBorder is the cols < borderMinThreshold
// fallback. Same shape as the pre-borders renderer (header row, body,
// status row, footer row) so very narrow terminals still produce a
// coherent display. Uses the same ops-driven content as the
// border-on path (closes #52).
func renderApprovalsPaneNoBorder(b *strings.Builder, m Model, rows int) {
	displayed := DisplayedOps(m)
	pending := 0
	for _, o := range displayed {
		if o.Status == opstream.StatusPending {
			pending++
		}
	}
	header := formatOpsPaneLabelText(len(displayed), pending)
	if m.Focused == PaneApprovals {
		b.WriteString(boldLine("▶ "+header, m.Cols))
	} else {
		b.WriteString(dimLine("  "+header, m.Cols))
	}
	b.WriteString("\r\n")

	bodyLines := rows - 3
	if bodyLines < 1 {
		bodyLines = 1
	}
	used := 0
	if len(displayed) == 0 {
		b.WriteString(padRight("  (no recent operations — waiting for traffic)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		const methodW, countW, statusW, timeW = 7, 1, 11, 14
		urlW := m.Cols - methodW - countW - statusW - timeW - 6
		if urlW < 8 {
			urlW = 8
		}
		colHeader := fmt.Sprintf(" %-*s %-*s %s %-*s %s",
			methodW, "METHOD", urlW, "URL", " ", statusW, "STATUS", "TIME")
		b.WriteString(padRight(colHeader, m.Cols))
		b.WriteString("\r\n")
		used++
		now := time.Now()
		for i, o := range displayed {
			if used >= bodyLines {
				break
			}
			urlCell := runeTrunc(o.URL, urlW)
			urlCellPadded := padRight(urlCell, urlW)
			row := fmt.Sprintf(" %-*s %s %s %-*s %s",
				methodW, runeTrunc(o.Method, methodW),
				colorizeURLForRow(urlCellPadded, o.URL),
				brailleCounter(o.Count),
				statusW, colorizeStatus(o.Status),
				formatOpTime(o.UpdatedAt, now),
			)
			if i == m.Selected {
				b.WriteString("\x1b[7m")
				b.WriteString(padRightVisible(row, m.Cols))
				b.WriteString("\x1b[0m")
			} else {
				b.WriteString(padRightVisible(row, m.Cols))
			}
			b.WriteString("\r\n")
			used++
		}
	}
	for used < bodyLines {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}

	if m.LastErr != "" {
		b.WriteString("\x1b[31m")
		b.WriteString(padRight(runeTrunc("error: "+m.LastErr, m.Cols), m.Cols))
		b.WriteString("\x1b[0m\r\n")
	} else if m.LastInfo != "" {
		b.WriteString("\x1b[32m")
		b.WriteString(padRight(runeTrunc(m.LastInfo, m.Cols), m.Cols))
		b.WriteString("\x1b[0m\r\n")
	} else {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
	}

	footer := "[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit"
	b.WriteString("\x1b[2m")
	b.WriteString(padRight(runeTrunc(footer, m.Cols), m.Cols))
	b.WriteString("\x1b[0m\r\n")
}

func renderConsolePane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneConsole
	if m.Cols < borderMinThreshold {
		renderConsolePaneNoBorder(b, m, rows)
		return
	}
	label := formatPaneLabel("console — type help", focused)
	rightHint := ""
	if focused {
		rightHint = formatTabHint(m.Focused)
	}
	b.WriteString(topBorder(label, rightHint, m.Cols, focused))

	// Body: rows - 1 top border - 1 bottom border - 1 prompt row.
	bodyLines := rows - 3
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	scroll := m.Console.Scrollback
	start := 0
	if len(scroll) > bodyLines {
		start = len(scroll) - bodyLines
	}
	used := 0
	for _, line := range scroll[start:] {
		b.WriteString(bodyLine(padRight(runeTrunc(line, inner), inner), m.Cols, focused))
		used++
	}
	for used < bodyLines {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
		used++
	}

	// Prompt row: prompt + input + cursor (when focused). Lives inside
	// the border, above the bottom border.
	prompt := m.Console.Prompt
	if prompt == "" {
		prompt = "trollbridge> "
	}
	input := string(m.Console.Input)
	visible := prompt + input
	if focused {
		visible += "█"
	}
	b.WriteString(bodyLine(padRight(runeTrunc(visible, inner), inner), m.Cols, focused))

	// Bottom border carries the Ctrl-C quit hint on the left.
	b.WriteString(bottomBorder("[Ctrl-C] quit", "", m.Cols, focused))
}

// renderConsolePaneNoBorder is the cols < borderMinThreshold fallback.
func renderConsolePaneNoBorder(b *strings.Builder, m Model, rows int) {
	header := "console — type help"
	if m.Focused == PaneConsole {
		b.WriteString(boldLine("▶ "+header, m.Cols))
	} else {
		b.WriteString(dimLine("  "+header, m.Cols))
	}
	b.WriteString("\r\n")

	bodyLines := rows - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	scroll := m.Console.Scrollback
	start := 0
	if len(scroll) > bodyLines {
		start = len(scroll) - bodyLines
	}
	used := 0
	for _, line := range scroll[start:] {
		b.WriteString(padRight(runeTrunc(line, m.Cols), m.Cols))
		b.WriteString("\r\n")
		used++
	}
	for used < bodyLines {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}

	prompt := m.Console.Prompt
	if prompt == "" {
		prompt = "trollbridge> "
	}
	input := string(m.Console.Input)
	visible := prompt + input
	if m.Focused == PaneConsole {
		visible += "█"
	}
	b.WriteString(padRight(runeTrunc(visible, m.Cols), m.Cols))
	b.WriteString("\r\n")
}

func boldLine(s string, cols int) string {
	return "\x1b[1m" + padRight(runeTrunc(s, cols), cols) + "\x1b[0m"
}

func dimLine(s string, cols int) string {
	return "\x1b[2m" + padRight(runeTrunc(s, cols), cols) + "\x1b[0m"
}

func padRight(s string, width int) string {
	rs := []rune(s)
	if len(rs) >= width {
		return string(rs[:width])
	}
	return s + strings.Repeat(" ", width-len(rs))
}

func runeTrunc(s string, width int) string {
	rs := []rune(s)
	if len(rs) <= width {
		return s
	}
	if width <= 1 {
		return string(rs[:width])
	}
	return string(rs[:width-1]) + "…"
}

// renderBottomPane dispatches to one of four panel renderers per
// Model.BottomPanel. The numbered key shortcuts (1-4 with approvals
// focused) cycle the selection; the default is the console pane,
// preserving prior behavior (closes #66).
func renderBottomPane(b *strings.Builder, m Model, rows int) {
	switch m.BottomPanel {
	case BottomPanelInfo:
		renderInfoPane(b, m, rows)
	case BottomPanelLLM:
		renderLLMPane(b, m, rows)
	case BottomPanelURLs:
		renderURLsPane(b, m, rows)
	default:
		renderConsolePane(b, m, rows)
	}
}

// panelHeaderLine renders the panel title row + the keystroke hint
// reminding the operator how to switch panels and how to hide them
// back to approvals-only.
func panelHeaderLine(b *strings.Builder, m Model, title string) {
	hint := "[0]hide  [1]console  [2]info  [3]llm  [4]urls"
	left := title
	right := hint
	gap := m.Cols - len([]rune(left)) - len([]rune(right))
	if gap < 1 {
		gap = 1
	}
	b.WriteString(left + strings.Repeat(" ", gap) + right)
	b.WriteString("\r\n")
}

// renderInfoPane shows the full detail of the currently selected op
// inside a focus-colored border. Layout splits group-identity (top)
// from most-recent-request stats (bottom) per #90.
func renderInfoPane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneConsole
	if m.Cols < borderMinThreshold {
		renderInfoPaneNoBorder(b, m, rows)
		return
	}
	label := formatPaneLabel("info", focused)
	rightHint := ""
	if focused {
		rightHint = formatTabHint(m.Focused)
	}
	b.WriteString(topBorder(label, rightHint, m.Cols, focused))

	bodyLines := rows - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	used := 0
	writeRow := func(s string) {
		if used >= bodyLines {
			return
		}
		b.WriteString(bodyLine(padRight(runeTrunc(s, inner), inner), m.Cols, focused))
		used++
	}
	for _, line := range infoPaneLines(m) {
		writeRow(line)
	}
	for used < bodyLines {
		writeRow("")
	}
	b.WriteString(bottomBorder(panelSwitcherHint, "", m.Cols, focused))
}

// renderInfoPaneNoBorder is the cols < borderMinThreshold fallback
// for the info pane — same two-section layout as the bordered
// version, without the chrome (closes #88, #90).
func renderInfoPaneNoBorder(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── info ── ")
	used := 1
	for _, l := range infoPaneLines(m) {
		if used >= rows {
			break
		}
		b.WriteString(padRight(runeTrunc(l, m.Cols), m.Cols))
		b.WriteString("\r\n")
		used++
	}
	for used < rows {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}
}

// infoPaneLines builds the body of the info pane as an ordered slice
// of pre-formatted lines, factoring the two-section layout (group
// identity + most-recent request) shared by the bordered and
// no-border renderers (#90).
func infoPaneLines(m Model) []string {
	displayed := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(displayed) {
		return []string{"  (no operation selected — Tab to approvals, j/k to pick)"}
	}
	o := displayed[m.Selected]
	lines := []string{
		"  \x1b[2mrequest\x1b[0m",
		fmt.Sprintf("    method     : %s", o.Method),
		fmt.Sprintf("    url        : %s", o.URL),
		fmt.Sprintf("    count      : %d", o.Count),
		"",
		"  \x1b[2mmost recent\x1b[0m",
		fmt.Sprintf("    status     : %s", o.Status),
	}
	if o.HoldID != "" {
		lines = append(lines, fmt.Sprintf("    hold_id    : %s", o.HoldID))
	}
	lines = append(lines,
		fmt.Sprintf("    started    : %s", o.StartedAt.Local().Format("2006-01-02 15:04:05")),
		fmt.Sprintf("    latency    : %s", formatInfoLatency(o.LatencyMS)),
		fmt.Sprintf("    response   : %s", formatInfoBytes(o.ResponseSizeBytes)),
	)
	return lines
}

// formatInfoLatency renders the latency cell of the info pane: "Nms"
// when known, "—" when 0 (in-flight or not yet resolved).
func formatInfoLatency(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return fmt.Sprintf("%dms", ms)
}

// formatInfoBytes renders the response-size cell of the info pane:
// raw byte count when known, "—" when 0 (in-flight or no-body case
// such as TLS handshake failure).
func formatInfoBytes(n int64) string {
	if n <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d bytes", n)
}

// panelSwitcherHint is the global bottom-panel switcher reminder
// shared across info/llm/urls panels' bottom borders (closes #88).
const panelSwitcherHint = "[0]hide  [1]console  [2]info  [3]llm  [4]urls"

// llmDetailLineCount is the conservative line-count estimate used by
// the modal-promotion decision (`shouldRenderLLMModal`). The detail
// block has 7 base fields (request_id row dropped per #92) plus
// optional wrap continuations for `url` and `reason` (#91); the
// budget covers up to 3 wrap lines across both.
const llmDetailLineCount = 10

// llmSelectionBar is the leading marker for the selected digest's
// rows (#91). Replaces the old inverse-video block highlight. Two
// cells wide so unselected rows can align with a two-space pad.
const llmSelectionBar = "┃ "
const llmSelectionPad = "  "

// llmDetailFitsInline reports whether the LLM panel's inline-expand
// layout has enough room to render the detail block plus the panel
// chrome (top + bottom border) plus at least one peer digest row.
// When false, render promotes the detail view to a full-body modal
// instead.
//
// detailLines is the actual number of detail rows for the currently
// selected digest at the current panel width — see
// llmDetailLineCountFor. Pre-#105 cleanup, this was a static
// estimate (llmDetailLineCount=10); the actual count is exact and
// avoids both the false-promote-to-modal and the false-inline-then-
// clip failure modes.
func llmDetailFitsInline(panelRows, detailLines int) bool {
	// 2 border rows + detail block + at least 1 peer row.
	return panelRows >= 2+detailLines+1
}

// llmDetailLineCountFor returns the actual wrapped line count of
// the LLM detail block for the selected digest at the current
// panel width. Falls back to the conservative llmDetailLineCount
// estimate when no digest is selected (the modal-promotion check
// still needs a reasonable answer).
func llmDetailLineCountFor(m Model) int {
	if m.DigestSelected == "" || len(m.Digests) == 0 {
		return llmDetailLineCount
	}
	// Find the selected digest in the ring.
	var d advisor.Digest
	found := false
	for _, x := range m.Digests {
		if x.RequestID == m.DigestSelected {
			d = x
			found = true
			break
		}
	}
	if !found {
		return llmDetailLineCount
	}
	// Wrap width = panel cols minus 2 borders. Match the renderer's
	// wrap width so the count is accurate.
	width := m.Cols - 2
	if width <= 0 {
		return llmDetailLineCount
	}
	return len(digestDetailLines(d, width))
}

// shouldRenderLLMModal reports whether the top-level render must
// suppress the normal two-pane layout and draw the modal LLM detail
// view in its place. True iff the LLM panel is open, the user has
// expanded a selected digest, and the inline expansion would not
// fit (closes #81).
func shouldRenderLLMModal(m Model, bodyRows int) bool {
	if !m.BottomPanelOpen || m.BottomPanel != BottomPanelLLM {
		return false
	}
	if !m.DigestExpanded || m.DigestSelected == "" {
		return false
	}
	// Bottom-pane allocation in the normal split: half the body
	// (mirroring render). If that allocation would not fit the
	// inline expansion, promote.
	topRows := bodyRows / 2
	if topRows < 3 {
		topRows = 3
	}
	bottomRows := bodyRows - topRows
	if bottomRows < 3 {
		bottomRows = 3
	}
	return !llmDetailFitsInline(bottomRows, llmDetailLineCountFor(m))
}

// digestDetailLines formats the per-digest detail block as a fixed-
// label list, with url and reason wrapped to the supplied width if
// it's set (#91). request_id is omitted per #92. width <= 0 means
// "no wrap — return one line per field".
func digestDetailLines(d advisor.Digest, width int) []string {
	url := fmt.Sprintf("%s://%s:%d%s", d.Scheme, d.Host, d.Port, d.Path)
	out := []string{
		fmt.Sprintf("  time       : %s", d.Timestamp.Local().Format("2006-01-02 15:04:05")),
		fmt.Sprintf("  method     : %s", d.Method),
	}
	out = append(out, wrapAfterLabel("  url        : ", url, width)...)
	out = append(out,
		fmt.Sprintf("  effect     : %s   confidence: %s", d.Effect, d.Confidence),
		fmt.Sprintf("  outcome    : %s", d.Outcome),
		fmt.Sprintf("  advisor_id : %s", d.AdvisorID),
	)
	out = append(out, wrapAfterLabel("  reason     : ", d.Reason, width)...)
	return out
}

// wrapAfterLabel emits a multi-line slice for a labelled value:
// the first line begins with the label, continuation lines indent
// to align under the value column. Wrapping is greedy on whitespace
// boundaries; a word longer than the value column is allowed to
// overflow (rare in practice for URLs without spaces — see fallback
// in the loop).
func wrapAfterLabel(label, value string, width int) []string {
	if width <= 0 {
		return []string{label + value}
	}
	labelW := runeLen(label)
	if width <= labelW+1 {
		return []string{label + value}
	}
	valueW := width - labelW
	indent := strings.Repeat(" ", labelW)
	if runeLen(value) <= valueW {
		return []string{label + value}
	}
	// Greedy word-wrap on spaces. URLs without spaces fall through
	// to character-wrap.
	var out []string
	rest := value
	first := true
	for runeLen(rest) > valueW {
		cut := lastSpaceWithin(rest, valueW)
		if cut <= 0 {
			cut = valueW
		}
		chunk := strings.TrimRight(rest[:cut], " ")
		if first {
			out = append(out, label+chunk)
			first = false
		} else {
			out = append(out, indent+chunk)
		}
		rest = strings.TrimLeft(rest[cut:], " ")
	}
	if rest != "" {
		if first {
			out = append(out, label+rest)
		} else {
			out = append(out, indent+rest)
		}
	}
	return out
}

// lastSpaceWithin returns the byte index of the last ASCII space at
// or before column `maxCol` (counted in runes), or -1 if none.
func lastSpaceWithin(s string, maxCol int) int {
	col := 0
	lastSpace := -1
	for i, r := range s {
		if col >= maxCol {
			break
		}
		if r == ' ' {
			lastSpace = i
		}
		col++
	}
	return lastSpace
}

// leadingMark returns the per-row prefix used by the LLM panel
// (#91): a focus-colored bar `┃ ` for the selected digest (and its
// wrap continuations), or two spaces of padding for everything
// else. The bar replaces the previous inverse-video highlight.
func leadingMark(selected, focused bool) string {
	if !selected {
		return llmSelectionPad
	}
	color := colorUnfocused
	if focused {
		color = colorFocused
	}
	return color + llmSelectionBar + colorReset
}

// renderLLMPane shows the rolling advisor-classify digest inside a
// focus-colored border (closes #88). Navigation and Enter-to-expand
// semantics (#81) are unchanged; only the chrome around the body
// changed.
func renderLLMPane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneConsole
	if m.Cols < borderMinThreshold {
		renderLLMPaneNoBorder(b, m, rows)
		return
	}
	label := formatPaneLabel("llm", focused)
	rightHint := ""
	if focused {
		rightHint = formatTabHint(m.Focused)
	}
	b.WriteString(topBorder(label, rightHint, m.Cols, focused))

	bodyLines := rows - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	// Body content fills `inner` cells; subtract the leading mark
	// (`┃ ` / `  `) when computing the wrap budget per row.
	contentWidth := inner - runeLen(llmSelectionPad)
	if contentWidth < 1 {
		contentWidth = 1
	}
	used := 0
	writeLine := func(s string, selected bool) {
		if used >= bodyLines {
			return
		}
		mark := leadingMark(selected, focused)
		body := padRight(runeTrunc(s, contentWidth), contentWidth)
		b.WriteString(bodyLine(mark+body, m.Cols, focused))
		used++
	}
	if len(m.Digests) == 0 {
		writeLine("(no LLM evaluations yet — advisor disabled or no traffic)", false)
	} else {
		for i := len(m.Digests) - 1; i >= 0 && used < bodyLines; i-- {
			d := m.Digests[i]
			selected := d.RequestID == m.DigestSelected
			if selected && m.DigestExpanded {
				for _, line := range digestDetailLines(d, contentWidth) {
					if used >= bodyLines {
						break
					}
					writeLine(line, true)
				}
				continue
			}
			ts := d.Timestamp.Local().Format("15:04:05")
			line := fmt.Sprintf("%s  %-7s %-7s %s  — %s",
				ts, d.Effect, d.Confidence, d.Host, d.Reason)
			writeLine(line, selected)
		}
	}
	for used < bodyLines {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
		used++
	}
	b.WriteString(bottomBorder("[↑↓/jk] nav  [Enter] collapse/expand  [Esc] close", panelSwitcherHint, m.Cols, focused))
}

// renderLLMPaneNoBorder is the narrow-terminal fallback for the LLM
// pane — same wrap + side-bar conventions as the bordered version
// (#91), without the box-drawing chrome.
func renderLLMPaneNoBorder(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── llm ── [↑↓/jk] nav  [Enter] collapse/expand  [Esc] close ")
	used := 1
	focused := m.Focused == PaneConsole
	contentWidth := m.Cols - runeLen(llmSelectionPad)
	if contentWidth < 1 {
		contentWidth = 1
	}
	writeLine := func(s string, selected bool) {
		if used >= rows {
			return
		}
		mark := leadingMark(selected, focused)
		body := padRight(runeTrunc(s, contentWidth), contentWidth)
		b.WriteString(mark + body)
		b.WriteString("\r\n")
		used++
	}
	if len(m.Digests) == 0 {
		writeLine("(no LLM evaluations yet — advisor disabled or no traffic)", false)
		for used < rows {
			b.WriteString(padRight("", m.Cols))
			b.WriteString("\r\n")
			used++
		}
		return
	}
	for i := len(m.Digests) - 1; i >= 0 && used < rows; i-- {
		d := m.Digests[i]
		selected := d.RequestID == m.DigestSelected
		if selected && m.DigestExpanded {
			for _, line := range digestDetailLines(d, contentWidth) {
				if used >= rows {
					break
				}
				writeLine(line, true)
			}
			continue
		}
		ts := d.Timestamp.Local().Format("15:04:05")
		line := fmt.Sprintf("%s  %-7s %-7s %s  — %s",
			ts, d.Effect, d.Confidence, d.Host, d.Reason)
		writeLine(line, selected)
	}
	for used < rows {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}
}

// renderLLMModal draws the full-body LLM detail view when the
// inline expansion would not fit. The modal takes over both the
// approvals pane and the bottom pane region; the operator returns
// to the panel with Esc (#81). Detail content wraps to the full
// terminal width (#91).
func renderLLMModal(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── llm detail ── [Esc] back  [0]/[3] close ")
	used := 1
	var d advisor.Digest
	found := false
	for _, cand := range m.Digests {
		if cand.RequestID == m.DigestSelected {
			d = cand
			found = true
			break
		}
	}
	if !found {
		b.WriteString(padRight("  (selected digest no longer in ring — Esc to return)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		for _, line := range digestDetailLines(d, m.Cols) {
			if used >= rows {
				break
			}
			b.WriteString(padRight(runeTrunc(line, m.Cols), m.Cols))
			b.WriteString("\r\n")
			used++
		}
	}
	for used < rows {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}
}

// urlsLine is one rendered row of the URLs panel: a header
// (ALLOW/DENY) or an entry. Used by the renderer to compute a
// scroll window stateless from the cursor position (closes #84).
type urlsLine struct {
	text     string
	selected bool
}

// buildURLsLines flattens the allow/deny lists into the logical
// row sequence the renderer draws: ALLOW header, allow entries
// (or (empty)), DENY header, deny entries (or (empty)). The
// selected flag is set on the entry whose combined-list index
// matches m.URLsSelected.
func buildURLsLines(m Model) []urlsLine {
	lines := make([]urlsLine, 0, 2+len(m.AllowList)+len(m.DenyList)+2)
	lines = append(lines, urlsLine{text: fmt.Sprintf("  ALLOW (%d)", len(m.AllowList))})
	if len(m.AllowList) == 0 {
		lines = append(lines, urlsLine{text: "    (empty)"})
	} else {
		for i, p := range m.AllowList {
			lines = append(lines, urlsLine{text: "    " + p, selected: m.URLsSelected == i})
		}
	}
	lines = append(lines, urlsLine{text: fmt.Sprintf("  DENY (%d)", len(m.DenyList))})
	if len(m.DenyList) == 0 {
		lines = append(lines, urlsLine{text: "    (empty)"})
	} else {
		allowLen := len(m.AllowList)
		for i, p := range m.DenyList {
			lines = append(lines, urlsLine{text: "    " + p, selected: m.URLsSelected == allowLen+i})
		}
	}
	return lines
}

// urlsScrollOffset computes the index of the first visible
// logical row given the cursor row, the body rows available, and
// the total number of logical rows. Centred-cursor rule: try to
// place the cursor in the middle of the visible window, clamped
// at the start and end of the list. Stateless — no Model field
// (closes #84).
func urlsScrollOffset(cursorRow, bodyRows, total int) int {
	if bodyRows <= 0 || total <= bodyRows {
		return 0
	}
	first := cursorRow - bodyRows/2
	if first < 0 {
		first = 0
	}
	if maxFirst := total - bodyRows; first > maxFirst {
		first = maxFirst
	}
	return first
}

// renderURLsPane shows the allow/deny lists from trollbridge.yaml
// inside a focus-colored border (closes #88). The list editor
// semantics (#79/#86), cursor-tracking scroll (#84), and attach-mode
// hint are unchanged; only the chrome around the body changed.
func renderURLsPane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneConsole
	if m.Cols < borderMinThreshold {
		renderURLsPaneNoBorder(b, m, rows)
		return
	}
	label := formatPaneLabel("urls", focused)
	rightHint := ""
	if focused {
		rightHint = formatTabHint(m.Focused)
	}
	b.WriteString(topBorder(label, rightHint, m.Cols, focused))

	bodyLines := rows - 2
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	used := 0
	writeRow := func(text string, selected bool) {
		if used >= bodyLines {
			return
		}
		cell := padRight(runeTrunc(text, inner), inner)
		if selected {
			cell = "\x1b[7m" + cell + "\x1b[0m"
		}
		b.WriteString(bodyLine(cell, m.Cols, focused))
		used++
	}

	if !m.URLsLocal {
		writeRow("  (allow/deny editing runs on the proxy host — open `trollbridge run` there)", false)
	} else {
		lines := buildURLsLines(m)
		cursorRow := -1
		for i, ln := range lines {
			if ln.selected {
				cursorRow = i
				break
			}
		}
		first := 0
		if cursorRow >= 0 {
			first = urlsScrollOffset(cursorRow, bodyLines, len(lines))
		}
		end := first + bodyLines
		if end > len(lines) {
			end = len(lines)
		}
		for i := first; i < end; i++ {
			writeRow(lines[i].text, lines[i].selected)
		}
	}
	for used < bodyLines {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
		used++
	}
	urlsHint := "[jk] nav  [a/d] approve/deny  [+] add  [e] edit  [g] generalize  [del] rm  [^z] undo"
	b.WriteString(bottomBorder(urlsHint, panelSwitcherHint, m.Cols, focused))
}

// renderURLsPaneNoBorder is the narrow-terminal fallback.
func renderURLsPaneNoBorder(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── urls ── [jk] nav  [a/d] approve/deny  [+] add  [e] edit  [g] generalize  [del] rm  [^z] undo ")
	used := 1
	if !m.URLsLocal {
		b.WriteString(padRight("  (allow/deny editing runs on the proxy host — open `trollbridge run` there)", m.Cols))
		b.WriteString("\r\n")
		used++
		for used < rows {
			b.WriteString(padRight("", m.Cols))
			b.WriteString("\r\n")
			used++
		}
		return
	}
	lines := buildURLsLines(m)
	bodyRows := rows - used
	if bodyRows < 0 {
		bodyRows = 0
	}
	cursorRow := -1
	for i, ln := range lines {
		if ln.selected {
			cursorRow = i
			break
		}
	}
	first := 0
	if cursorRow >= 0 {
		first = urlsScrollOffset(cursorRow, bodyRows, len(lines))
	}
	end := first + bodyRows
	if end > len(lines) {
		end = len(lines)
	}
	for i := first; i < end; i++ {
		text := lines[i].text
		if lines[i].selected {
			b.WriteString("\x1b[7m")
			b.WriteString(padRight(runeTrunc(text, m.Cols), m.Cols))
			b.WriteString("\x1b[0m")
		} else {
			b.WriteString(padRight(runeTrunc(text, m.Cols), m.Cols))
		}
		b.WriteString("\r\n")
		used++
	}
	for used < rows {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}
}

// filterListEntries strips blank/comment rows from a list as
// loaded from trollbridge.yaml. The URLs pane only navigates over
// real entries so removal semantics line up with what the
// configwrite remove path actually matches.
func filterListEntries(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		t := strings.TrimSpace(e)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}
