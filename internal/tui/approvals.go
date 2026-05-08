package tui

import (
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

// RunApprovals starts the approvals TUI bound to in/out and the
// daemon described by cfg. It returns when the operator quits or
// ctx is cancelled. The terminal is always restored on return,
// including on panic.
func RunApprovals(ctx context.Context, cfg *config.Config, in, out *os.File) (err error) {
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return errors.New("trollbridge tui: stdin/stdout is not a terminal")
	}
	oldState, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return fmt.Errorf("trollbridge tui: enter raw mode: %w", err)
	}
	defer func() {
		// Always restore the cooked terminal state. Hide-cursor / alt-
		// screen state is reset before restore so the operator's shell
		// looks normal afterwards.
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), oldState)
		if r := recover(); r != nil {
			err = fmt.Errorf("trollbridge tui: panic: %v", r)
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

	return runLoop(ctx, &httpClient{cfg: cfg}, in, out, out, cols, rows)
}

// runLoop is the testable inner loop. resize may be nil in tests.
func runLoop(ctx context.Context, client ControlClient, in io.Reader, out io.Writer, resize *os.File, cols, rows int) error {
	model := Model{Selected: -1, Cols: cols, Rows: rows}

	events := make(chan Event, 32)
	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()

	go readKeys(loopCtx, in, events)
	go tickRefresh(loopCtx, client, events)
	if resize != nil {
		go watchResize(loopCtx, resize, events)
	}

	// First paint with empty list before the first tick lands.
	_ = render(out, model)

	for {
		// External cancellation (parent ctx) — clean exit.
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
		}
	}
}

// readKeys reads from the operator's stdin in raw mode, parses
// printable runes and a small set of ANSI escape sequences (arrow
// keys, Esc, Ctrl-C), and forwards KeyEvents.
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
				select {
				case <-ctx.Done():
					return
				case events <- KeyEvent{Key: KeyCtrlC}:
				}
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

// render draws the current model to out using ANSI escapes.
func render(out io.Writer, m Model) error {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // home + clear

	// Header.
	b.WriteString(boldLine(fmt.Sprintf("trollbridge approvals — %d pending", len(m.Holds)), m.Cols))
	b.WriteString("\r\n")

	// Body.
	if len(m.Holds) == 0 {
		b.WriteString("\r\n  (no pending holds — waiting for new requests)\r\n")
	} else {
		// Column widths: id 12, identity 14, host:port up to 36, path remainder.
		const idW, idtyW, hostW = 12, 14, 36
		header := fmt.Sprintf(" %-*s  %-*s  %-*s  %s",
			idW, "ID", idtyW, "IDENTITY", hostW, "HOST:PORT", "PATH")
		b.WriteString(padRight(header, m.Cols))
		b.WriteString("\r\n")
		for i, h := range m.Holds {
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
		}
	}

	// Footer.
	b.WriteString("\r\n")
	if m.LastErr != "" {
		b.WriteString("\x1b[31m") // red
		b.WriteString(runeTrunc("error: "+m.LastErr, m.Cols))
		b.WriteString("\x1b[0m\r\n")
	} else if m.LastInfo != "" {
		b.WriteString("\x1b[32m") // green
		b.WriteString(runeTrunc(m.LastInfo, m.Cols))
		b.WriteString("\x1b[0m\r\n")
	} else {
		b.WriteString("\r\n")
	}
	b.WriteString("\x1b[2m") // dim
	b.WriteString(runeTrunc("[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit", m.Cols))
	b.WriteString("\x1b[0m\r\n")

	_, err := io.WriteString(out, b.String())
	return err
}

func boldLine(s string, cols int) string {
	return "\x1b[1m" + padRight(runeTrunc(s, cols), cols) + "\x1b[0m"
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
