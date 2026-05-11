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
	// to advisor.Service.Digests(). HTTP clients currently return
	// nil (control-plane /v1/llm-digests endpoint is a follow-up).
	RecentLLMDigests() ([]advisor.Digest, error)
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
	// Control-plane /v1/llm-digests endpoint is a follow-up
	// (filed in job 120's improvements). Until then, attach mode
	// shows an empty LLM panel.
	return nil, nil
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
func RunOperator(ctx context.Context, client ControlClient, in, out *os.File, backend *console.Backend, welcome string, requestShutdown func()) (err error) {
	return runWithClient(ctx, in, out, client, backend, welcome, requestShutdown)
}

func runWithClient(ctx context.Context, in, out *os.File, client ControlClient, backend *console.Backend, welcome string, requestShutdown func()) (err error) {
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

	return runLoop(ctx, client, backend, in, out, out, cols, rows, welcome, requestShutdown)
}

// runLoop is the testable inner loop. resize may be nil in tests.
// requestShutdown, when non-nil, is invoked when the loop exits via
// operator-initiated quit (CmdQuit) — see RunOperator for rationale.
// It is NOT invoked when the loop exits because ctx is already done
// (the parent is already shutting down for another reason).
func runLoop(ctx context.Context, client ControlClient, backend *console.Backend, in io.Reader, out io.Writer, resize *os.File, cols, rows int, welcome string, requestShutdown func()) error {
	model := Model{
		Selected: -1,
		Cols:     cols,
		Rows:     rows,
		Focused:  PaneApprovals,
		Console:  ConsoleModel{Prompt: "trollbridge> "},
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
			case b == 0x1b: // ESC, possibly start of a CSI sequence
				if i+2 < n && buf[i+1] == '[' {
					switch buf[i+2] {
					case 'A':
						sendKey(ctx, events, KeyEvent{Key: KeyUp})
					case 'B':
						sendKey(ctx, events, KeyEvent{Key: KeyDown})
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
	label := formatPaneLabel(fmt.Sprintf("trollbridge operations — %d total · %d pending", len(displayed), pending), focused)
	rightHint := ""
	if focused {
		rightHint = formatTabHint(m.Focused)
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
	if m.LastErr != "" {
		row := "\x1b[31m" + padRight(runeTrunc("error: "+m.LastErr, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLine(row, m.Cols, focused))
	} else if m.LastInfo != "" {
		row := "\x1b[32m" + padRight(runeTrunc(m.LastInfo, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLine(row, m.Cols, focused))
	} else {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
	}

	// Bottom border carries the keybindings on the right.
	keys := "[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit"
	b.WriteString(bottomBorder("", keys, m.Cols, focused))
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
	case opstream.StatusError, opstream.StatusDenied:
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
	header := fmt.Sprintf("trollbridge operations — %d total · %d pending", len(displayed), pending)
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
// reminding the operator how to switch panels.
func panelHeaderLine(b *strings.Builder, m Model, title string) {
	hint := "[1]console  [2]info  [3]llm  [4]urls"
	left := title
	right := hint
	gap := m.Cols - len([]rune(left)) - len([]rune(right))
	if gap < 1 {
		gap = 1
	}
	b.WriteString(left + strings.Repeat(" ", gap) + right)
	b.WriteString("\r\n")
}

// renderInfoPane shows the full detail of the currently selected op.
func renderInfoPane(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── info ── ")
	used := 1
	displayed := DisplayedOps(m)
	if m.Selected < 0 || m.Selected >= len(displayed) {
		b.WriteString(padRight("  (no operation selected — Tab to approvals, j/k to pick)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		o := displayed[m.Selected]
		now := time.Now()
		lines := []string{
			fmt.Sprintf("  request_id : %s", o.RequestID),
			fmt.Sprintf("  method     : %s", o.Method),
			fmt.Sprintf("  url        : %s", o.URL),
			fmt.Sprintf("  status     : %s", o.Status),
			fmt.Sprintf("  hold_id    : %s", o.HoldID),
			fmt.Sprintf("  count      : %d", o.Count),
			fmt.Sprintf("  started    : %s", o.StartedAt.Local().Format("2006-01-02 15:04:05")),
			fmt.Sprintf("  updated    : %s  (%s ago)", o.UpdatedAt.Local().Format("2006-01-02 15:04:05"), now.Sub(o.UpdatedAt).Truncate(time.Second)),
		}
		for _, l := range lines {
			if used >= rows {
				break
			}
			b.WriteString(padRight(runeTrunc(l, m.Cols), m.Cols))
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

// renderLLMPane shows the rolling advisor-classify digest.
func renderLLMPane(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── llm ── ")
	used := 1
	if len(m.Digests) == 0 {
		b.WriteString(padRight("  (no LLM evaluations yet — advisor disabled or no traffic)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		// Newest first.
		for i := len(m.Digests) - 1; i >= 0 && used < rows; i-- {
			d := m.Digests[i]
			ts := d.Timestamp.Local().Format("15:04:05")
			line := fmt.Sprintf("  %s  %-7s %-7s %s  — %s",
				ts,
				d.Effect,
				d.Confidence,
				d.Host,
				d.Reason,
			)
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

// renderURLsPane shows the distinct URLs seen in the ops ring with
// the underlying repetition count.
func renderURLsPane(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── urls ── ")
	used := 1
	displayed := DisplayedOps(m)
	if len(displayed) == 0 {
		b.WriteString(padRight("  (no URLs yet)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		for _, o := range displayed {
			if used >= rows {
				break
			}
			line := fmt.Sprintf("  %4d  %-7s %s", o.Count, o.Method, o.URL)
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
