package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"golang.org/x/term"
)

// ControlClient is the small surface the TUI needs from the daemon's
// control API. The default implementation hits the daemon over HTTP;
// tests can stub it.
type ControlClient interface {
	ListHolds() ([]approvals.Snapshot, error)
	Approve(id string) error
	Deny(id, reason string) error
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

func (c *httpClient) Approve(id string) error {
	_, err := controlclient.HoldAction(c.cfg, id, "approve", "once", "")
	return err
}

func (c *httpClient) Deny(id, reason string) error {
	_, err := controlclient.HoldAction(c.cfg, id, "deny", "", reason)
	return err
}

// RunOperator is the unified entry point used by `trollbridge run`
// (LocalOnly backend) and `trollbridge attach` (remote backend with
// a ControlClient pointing at the daemon's HTTP control plane).
func RunOperator(ctx context.Context, cfg *config.Config, in, out *os.File, backend *console.Backend, welcome string) (err error) {
	return runWithClient(ctx, cfg, in, out, &httpClient{cfg: cfg}, backend, welcome)
}

// RunApprovals is preserved for callers that want only the approvals
// pane (legacy behavior). It now delegates to runWithClient with a
// minimal attach-mode backend so the layout is the same shape.
func RunApprovals(ctx context.Context, cfg *config.Config, in, out *os.File) (err error) {
	return runWithClient(ctx, cfg, in, out, &httpClient{cfg: cfg}, &console.Backend{LocalOnly: false}, "")
}

func runWithClient(ctx context.Context, cfg *config.Config, in, out *os.File, client ControlClient, backend *console.Backend, welcome string) (err error) {
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return errors.New("trollbridge ui: stdin/stdout is not a terminal")
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

	return runLoop(ctx, client, backend, in, out, out, cols, rows, welcome)
}

// runLoop is the testable inner loop. resize may be nil in tests.
func runLoop(ctx context.Context, client ControlClient, backend *console.Backend, in io.Reader, out io.Writer, resize *os.File, cols, rows int, welcome string) error {
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
			return nil
		}

		switch c := cmd.(type) {
		case CmdQuit:
			return nil
		case CmdRefresh:
			go func() {
				holds, err := client.ListHolds()
				select {
				case <-loopCtx.Done():
				case events <- TickResult{Holds: holds, Err: err}:
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
func tickRefresh(ctx context.Context, client ControlClient, events chan<- Event) {
	emit := func() {
		holds, err := client.ListHolds()
		select {
		case <-ctx.Done():
		case events <- TickResult{Holds: holds, Err: err}:
		}
	}
	emit()
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			emit()
		}
	}
}

// watchResize emits a ResizeEvent on every SIGWINCH.
func watchResize(ctx context.Context, out *os.File, events chan<- Event) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			cols, rows, _ := term.GetSize(int(out.Fd()))
			if cols == 0 {
				cols = 80
			}
			if rows == 0 {
				rows = 24
			}
			select {
			case <-ctx.Done():
				return
			case events <- ResizeEvent{Cols: cols, Rows: rows}:
			}
		}
	}
}

// render draws the current model to out using ANSI escapes. The
// terminal is split horizontally: the upper half hosts the approvals
// pane, the lower half hosts the console pane, and the bottom row
// is a one-line global hint.
func render(out io.Writer, m Model) error {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear

	if m.Cols < 1 {
		m.Cols = 80
	}
	if m.Rows < 6 {
		m.Rows = 24
	}

	// Reserve one row for the global hint at the very bottom.
	bodyRows := m.Rows - 1
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
	renderConsolePane(&b, m, bottomRows)
	renderGlobalHint(&b, m)

	_, err := io.WriteString(out, b.String())
	return err
}

func renderApprovalsPane(b *strings.Builder, m Model, rows int) {
	header := fmt.Sprintf("trollbridge approvals — %d pending", len(m.Holds))
	if m.Focused == PaneApprovals {
		b.WriteString(boldLine(header, m.Cols))
	} else {
		b.WriteString(dimLine(header, m.Cols))
	}
	b.WriteString("\r\n")

	// Body lines: rows - 1 header - 2 footer (status + hint).
	bodyLines := rows - 3
	if bodyLines < 1 {
		bodyLines = 1
	}
	used := 0
	if len(m.Holds) == 0 {
		b.WriteString(padRight("  (no pending holds — waiting for new requests)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		const idW, idtyW, hostW = 12, 14, 36
		colHeader := fmt.Sprintf(" %-*s  %-*s  %-*s  %s",
			idW, "ID", idtyW, "IDENTITY", hostW, "HOST:PORT", "PATH")
		b.WriteString(padRight(colHeader, m.Cols))
		b.WriteString("\r\n")
		used++
		for i, h := range m.Holds {
			if used >= bodyLines {
				break
			}
			row := fmt.Sprintf(" %-*s  %-*s  %-*s  %s",
				idW, runeTrunc(h.ID, idW),
				idtyW, runeTrunc(h.IdentityID, idtyW),
				hostW, runeTrunc(fmt.Sprintf("%s:%d", h.Host, h.Port), hostW),
				h.Path,
			)
			row = runeTrunc(row, m.Cols)
			if i == m.Selected {
				b.WriteString("\x1b[7m")
				b.WriteString(padRight(row, m.Cols))
				b.WriteString("\x1b[0m")
			} else {
				b.WriteString(padRight(row, m.Cols))
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

	// Status line.
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

	// Pane footer: keybindings (active when focused, dim hint when not).
	footer := "[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit"
	b.WriteString("\x1b[2m")
	b.WriteString(padRight(runeTrunc(footer, m.Cols), m.Cols))
	b.WriteString("\x1b[0m\r\n")
}

func renderConsolePane(b *strings.Builder, m Model, rows int) {
	header := "console — type help"
	if m.Focused == PaneConsole {
		b.WriteString(boldLine(header, m.Cols))
	} else {
		b.WriteString(dimLine(header, m.Cols))
	}
	b.WriteString("\r\n")

	// Reserve 1 row for the prompt at the bottom of the pane.
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

	// Prompt line: prompt + input. When the console pane is focused,
	// append a visible cursor block.
	prompt := m.Console.Prompt
	if prompt == "" {
		prompt = "trollbridge> "
	}
	input := string(m.Console.Input)
	visible := prompt + input
	if m.Focused == PaneConsole {
		visible += "█" // full block as a cursor
	}
	b.WriteString(padRight(runeTrunc(visible, m.Cols), m.Cols))
	b.WriteString("\r\n")
}

func renderGlobalHint(b *strings.Builder, m Model) {
	hint := "[Tab] switch panes  •  [Ctrl-C] quit"
	b.WriteString("\x1b[2m")
	b.WriteString(padRight(runeTrunc(hint, m.Cols), m.Cols))
	b.WriteString("\x1b[0m")
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
