package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/controlclient"
	"github.com/dandriscoll/trollbridge/internal/opstream"
	"github.com/dandriscoll/trollbridge/internal/reloadstatus"
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
	// ReloadStatus returns the daemon's most-recent hot-reload
	// outcome (closes #129). When the returned Status carries a
	// non-empty LastError, the approvals-pane header renders a
	// bold-red `␇ reload failed` badge so the operator notices that
	// the file on disk diverges from what the daemon is running.
	ReloadStatus() (reloadstatus.Status, error)
	// ActiveSuggestion returns the daemon's currently-offered quiet-
	// moment generalization suggestion, or (nil, nil) when there is
	// none (#172). AcceptSuggestion / DeclineSuggestion resolve it by
	// id through the daemon's suggestion lifecycle.
	ActiveSuggestion() (*Suggestion, error)
	AcceptSuggestion(id string) error
	DeclineSuggestion(id string) error
	// SkipSuggestion defers the active suggestion (#214): no decision
	// is persisted and the next recommendation is offered instead.
	SkipSuggestion(id string) error
	// SuggestNow asks the daemon to run the detector on demand
	// (#174) and returns the resulting suggestion (or nil).
	SuggestNow() (*Suggestion, error)
	// OpenModeState / ExtendOpenMode / CloseOpenMode drive the
	// time-boxed "allow all traffic" window (#209). State is polled for
	// the border/footer; Extend opens or extends; Close ends it. Each
	// returns the resulting (active, until). In-process clients reach
	// the server directly; HTTP clients call /v1/open.
	OpenModeState() (active bool, until time.Time, err error)
	ExtendOpenMode() (active bool, until time.Time, err error)
	CloseOpenMode() (active bool, until time.Time, err error)
}

// OpenModeController is the server-side surface the in-process client
// drives for open mode (#209). *server.Server satisfies it.
type OpenModeController interface {
	ExtendOpenMode() time.Time
	CloseOpenMode()
	OpenModeState() (active bool, until time.Time)
}

// SuggestionSource is the in-process surface of the daemon's
// suggestion lifecycle (#172/#174). The cmd layer adapts a
// *suggestion.Manager to it so the tui package needs no suggestion
// import. May be nil on the in-process client (no suggestions then).
type SuggestionSource interface {
	ActiveSuggestion() *Suggestion
	AcceptSuggestion(id string) error
	DeclineSuggestion(id string) error
	SkipSuggestion(id string) error
	SuggestNow() *Suggestion
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

func (c *httpClient) OpenModeState() (bool, time.Time, error) {
	return controlclient.OpenMode(c.cfg, http.MethodGet)
}

func (c *httpClient) ExtendOpenMode() (bool, time.Time, error) {
	return controlclient.OpenMode(c.cfg, http.MethodPost)
}

func (c *httpClient) CloseOpenMode() (bool, time.Time, error) {
	return controlclient.OpenMode(c.cfg, http.MethodDelete)
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

func (c *httpClient) ReloadStatus() (reloadstatus.Status, error) {
	// /v1/rules carries the most-recent reload outcome alongside the
	// rule set (the same endpoint /v1/rules returned pre-#129; the
	// new fields are omitempty so older daemons return zero-value
	// state and the badge stays quiet).
	body, gerr := controlclient.Get(c.cfg, "/v1/rules")
	if gerr != nil {
		return reloadstatus.Status{}, gerr
	}
	var resp reloadstatus.Status
	if uerr := json.Unmarshal(body, &resp); uerr != nil {
		return reloadstatus.Status{}, fmt.Errorf("decode rules: %w", uerr)
	}
	return resp, nil
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

func decodeSuggestion(body []byte) (*Suggestion, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil // 204: no active suggestion
	}
	var row struct {
		SuggestionID     string   `json:"suggestion_id"`
		Axis             string   `json:"axis"`
		List             string   `json:"list"`
		SourceEntries    []string `json:"source_entries"`
		SuggestedPattern string   `json:"suggested_pattern"`
		Reason           string   `json:"reason"`
		AxesRemaining    int      `json:"axes_remaining"`
	}
	if uerr := json.Unmarshal(body, &row); uerr != nil {
		return nil, fmt.Errorf("decode suggestion: %w", uerr)
	}
	return &Suggestion{
		ID:               row.SuggestionID,
		Axis:             row.Axis,
		List:             row.List,
		SourceEntries:    row.SourceEntries,
		SuggestedPattern: row.SuggestedPattern,
		Reason:           row.Reason,
		AxesRemaining:    row.AxesRemaining,
	}, nil
}

func (c *httpClient) ActiveSuggestion() (*Suggestion, error) {
	body, err := controlclient.Get(c.cfg, "/v1/suggestion")
	if err != nil {
		return nil, err
	}
	return decodeSuggestion(body)
}

func (c *httpClient) SuggestNow() (*Suggestion, error) {
	body, err := controlclient.Post(c.cfg, "/v1/suggestion/scan", nil)
	if err != nil {
		return nil, err
	}
	return decodeSuggestion(body)
}

func (c *httpClient) AcceptSuggestion(id string) error {
	body, _ := json.Marshal(map[string]string{"suggestion_id": id})
	_, err := controlclient.Post(c.cfg, "/v1/suggestion/accept", body)
	return err
}

func (c *httpClient) DeclineSuggestion(id string) error {
	body, _ := json.Marshal(map[string]string{"suggestion_id": id})
	_, err := controlclient.Post(c.cfg, "/v1/suggestion/decline", body)
	return err
}

func (c *httpClient) SkipSuggestion(id string) error {
	body, _ := json.Marshal(map[string]string{"suggestion_id": id})
	_, err := controlclient.Post(c.cfg, "/v1/suggestion/skip", body)
	return err
}

// NewHTTPClient returns a ControlClient that talks to the daemon's
// mTLS control plane. Used by `trollbridge attach` (separate process).
func NewHTTPClient(cfg *config.Config) ControlClient {
	return &httpClient{cfg: cfg}
}

// ReloadStatusSource is the in-process counterpart to /v1/rules'
// last_reload_* fields (closes #129). The daemon's *server.Server
// satisfies it via its ReloadStatus() method. Wired through the
// in-process client constructor so the TUI badge can render
// without an HTTP hop when the operator UI is embedded in
// `trollbridge run`.
type ReloadStatusSource interface {
	ReloadStatus() reloadstatus.Status
}

type inProcessClient struct {
	q   *approvals.Queue
	ops *opstream.Ring
	// adv is the advisor service whose Digests() ring backs the
	// LLM bottom panel (closes #66). May be nil if no advisor wired.
	adv *advisor.Service
	// reload is the daemon's reload-status surface (closes #129).
	// May be nil — the TUI badge then stays dormant.
	reload ReloadStatusSource
	// sugg is the daemon's suggestion lifecycle (#172). May be nil —
	// the suggestion card then never appears in the embedded UI.
	sugg SuggestionSource
	// om is the open-mode controller (#209). May be nil — open mode is
	// then reported as permanently closed and the keys no-op.
	om OpenModeController
}

// WithOpenMode wires an open-mode controller onto an in-process client
// (#209). No-op for other client types. Lets the run/quickstart call
// sites attach the server without widening every constructor signature.
func WithOpenMode(c ControlClient, om OpenModeController) ControlClient {
	if ip, ok := c.(*inProcessClient); ok {
		ip.om = om
	}
	return c
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
		return fmt.Errorf("%w: %s", controlclient.ErrHoldNotFound, id)
	}
	return nil
}

func (c *inProcessClient) Deny(id, reason string) error {
	if c.q == nil {
		return errors.New("approvals queue not initialized")
	}
	if !c.q.Deny(id, reason, "tui") {
		return fmt.Errorf("%w: %s", controlclient.ErrHoldNotFound, id)
	}
	return nil
}

func (c *inProcessClient) OpenModeState() (bool, time.Time, error) {
	if c.om == nil {
		return false, time.Time{}, nil
	}
	active, until := c.om.OpenModeState()
	return active, until, nil
}

func (c *inProcessClient) ExtendOpenMode() (bool, time.Time, error) {
	if c.om == nil {
		return false, time.Time{}, nil
	}
	c.om.ExtendOpenMode()
	active, until := c.om.OpenModeState()
	return active, until, nil
}

func (c *inProcessClient) CloseOpenMode() (bool, time.Time, error) {
	if c.om == nil {
		return false, time.Time{}, nil
	}
	c.om.CloseOpenMode()
	active, until := c.om.OpenModeState()
	return active, until, nil
}

func (c *inProcessClient) RecentLLMDigests() ([]advisor.Digest, error) {
	if c.adv == nil {
		return nil, nil
	}
	return c.adv.Digests().Snapshot(), nil
}

func (c *inProcessClient) ReloadStatus() (reloadstatus.Status, error) {
	if c.reload == nil {
		return reloadstatus.Status{}, nil
	}
	return c.reload.ReloadStatus(), nil
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

func (c *inProcessClient) ActiveSuggestion() (*Suggestion, error) {
	if c.sugg == nil {
		return nil, nil
	}
	return c.sugg.ActiveSuggestion(), nil
}

func (c *inProcessClient) AcceptSuggestion(id string) error {
	if c.sugg == nil {
		return errors.New("suggestion lifecycle not wired")
	}
	return c.sugg.AcceptSuggestion(id)
}

func (c *inProcessClient) DeclineSuggestion(id string) error {
	if c.sugg == nil {
		return errors.New("suggestion lifecycle not wired")
	}
	return c.sugg.DeclineSuggestion(id)
}

func (c *inProcessClient) SkipSuggestion(id string) error {
	if c.sugg == nil {
		return errors.New("suggestion lifecycle not wired")
	}
	return c.sugg.SkipSuggestion(id)
}

func (c *inProcessClient) SuggestNow() (*Suggestion, error) {
	if c.sugg == nil {
		return nil, nil
	}
	return c.sugg.SuggestNow(), nil
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

// NewInProcessClientFull wires the advisor and the reload-status
// source. The reload source (typically the daemon's *server.Server)
// drives the approvals-pane header badge for failed hot-reloads
// (closes #129). Any argument may be nil — the corresponding
// surface then renders empty.
func NewInProcessClientFull(q *approvals.Queue, ops *opstream.Ring, adv *advisor.Service, rs ReloadStatusSource) ControlClient {
	return &inProcessClient{q: q, ops: ops, adv: adv, reload: rs}
}

// NewInProcessClientWithSuggestion is NewInProcessClientFull plus the
// daemon's suggestion lifecycle (#172), so the embedded `trollbridge
// run` UI can surface and resolve quiet-moment generalization
// suggestions without an HTTP hop. sugg may be nil.
func NewInProcessClientWithSuggestion(q *approvals.Queue, ops *opstream.Ring, adv *advisor.Service, rs ReloadStatusSource, sugg SuggestionSource) ControlClient {
	return &inProcessClient{q: q, ops: ops, adv: adv, reload: rs, sugg: sugg}
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

	// History, when non-nil, drives the reversal-color indicator
	// on resolved rows (closes #192). Wired by the in-process
	// client over the policy engine's decision history; attach
	// passes nil and the reversal indicator is suppressed.
	History DecisionHistorySource

	// suspend, when non-nil, performs a job-control suspend (#176):
	// restore the cooked terminal, raise SIGTSTP so the host shell
	// regains control, and on resume (fg) re-enter raw mode + the
	// alt-screen. It blocks until the process is resumed. runWithClient
	// wires this with the live raw-mode state; tests leave it nil (the
	// `z` hotkey then no-ops). Unexported: only the TUI runtime sets it.
	suspend func()
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

	// Job-control suspend (#176). On `z` the loop calls this: drop the
	// alt-screen, restore cooked mode so the shell prompt is usable,
	// then stop ourselves with SIGTSTP. raiseSIGTSTP returns only once
	// the shell resumes us (fg / bg+fg), at which point we re-enter raw
	// mode + the alt-screen. oldState is refreshed so the deferred
	// Restore above still targets the operator's original termios.
	opts.suspend = func() {
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), oldState)
		raiseSIGTSTP()
		if st, e := term.MakeRaw(int(in.Fd())); e == nil {
			oldState = st
		}
		fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")
	}

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
		Selected:   -1,
		URLsAnchor: -1,
		Cols:       cols,
		Rows:       rows,
		Focused:    PaneApprovals,
		Console:    ConsoleModel{Prompt: "trollbridge> "},
		Alerts:     AlertsState{ChimeEnabled: opts.ChimeEnabled},
		History:    opts.History,
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

	consoleQueue := make(chan consoleJob, 8)
	go consoleWorker(loopCtx, backend, consoleQueue, events)

	go readKeys(loopCtx, in, events)
	go tickRefresh(loopCtx, client, events)
	if resize != nil {
		go watchResize(loopCtx, resize, events)
	}

	// prevFrame caches the last frame body so the delta renderer
	// can emit only the lines that changed (#202). The first paint
	// uses an empty prev so writeDeltaFrame falls back to a full
	// repaint; subsequent ticks emit just the dirty lines. An
	// explicit clear-screen (CmdRepaint, suspend resume) resets
	// prevFrame so the next render is full — the terminal canvas
	// the delta path assumes is no longer accurate after a hard
	// clear.
	var prevFrame string

	// First paint with empty list before the first tick lands.
	{
		frame := buildFrame(model)
		_ = writeDeltaFrame(out, frame, prevFrame)
		prevFrame = frame
	}

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
		if _, ok := cmd.(CmdRepaint); ok {
			// Hard repaint: clear visible, clear scrollback, home,
			// hide cursor. The subsequent render() call writes the
			// current frame on top of a known-clean terminal — the
			// affordance is vi's ^L (#115). Done before render so
			// the cleared canvas is what the next frame paints onto;
			// doing it after would clobber the just-rendered frame.
			_, _ = out.Write([]byte("\x1b[2J\x1b[3J\x1b[H\x1b[?25l"))
			prevFrame = "" // canvas is now blank; next frame must repaint in full
		}
		frame := buildFrame(model)
		_ = writeDeltaFrame(out, frame, prevFrame)
		prevFrame = frame

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
		case CmdSuspend:
			// Job-control suspend (#176). suspend() blocks until the
			// shell resumes us, then has re-entered raw mode + the
			// alt-screen; the alt-screen comes back blank, so force a
			// full redraw of the current frame.
			if opts.suspend != nil {
				opts.suspend()
				_, _ = out.Write([]byte("\x1b[2J\x1b[3J\x1b[H\x1b[?25l"))
				prevFrame = "" // alt-screen restored blank; next frame paints in full
				frame := buildFrame(model)
				_ = writeDeltaFrame(out, frame, prevFrame)
				prevFrame = frame
			}
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
			go func() {
				// Closes #129: refresh the failed-reload badge.
				// Same cadence as the holds/ops polls; one extra
				// /v1/rules request per tick. Cheap.
				st, err := client.ReloadStatus()
				select {
				case <-loopCtx.Done():
				case events <- ReloadTickResult{Status: st, Err: err}:
				}
			}()
		case CmdApprove:
			id, method, url := c.ID, c.Method, c.URL
			go func() {
				err := client.Approve(id)
				select {
				case <-loopCtx.Done():
				case events <- ActionResult{ID: id, Action: "approve", Method: method, URL: url, Err: err}:
				}
			}()
		case CmdDeny:
			id, method, url := c.ID, c.Method, c.URL
			go func() {
				err := client.Deny(id, "operator denied")
				select {
				case <-loopCtx.Done():
				case events <- ActionResult{ID: id, Action: "deny", Method: method, URL: url, Err: err}:
				}
			}()
		case CmdOpenMode:
			closeIt := c.Close
			go func() {
				var active bool
				var until time.Time
				var err error
				if closeIt {
					active, until, err = client.CloseOpenMode()
				} else {
					active, until, err = client.ExtendOpenMode()
				}
				select {
				case <-loopCtx.Done():
				case events <- OpenModeResult{Active: active, Until: until, Err: err}:
				}
			}()
		case CmdSuggestionAccept:
			id := c.ID
			go func() {
				err := client.AcceptSuggestion(id)
				select {
				case <-loopCtx.Done():
				case events <- SuggestionActionResult{Action: "accept", Err: err}:
				}
			}()
		case CmdSuggestionDecline:
			id := c.ID
			go func() {
				err := client.DeclineSuggestion(id)
				select {
				case <-loopCtx.Done():
				case events <- SuggestionActionResult{Action: "decline", Err: err}:
				}
			}()
		case CmdSuggestionSkip:
			id := c.ID
			go func() {
				err := client.SkipSuggestion(id)
				select {
				case <-loopCtx.Done():
				case events <- SuggestionActionResult{Action: "skip", Err: err}:
				}
			}()
		case CmdSuggestNow:
			go func() {
				sug, err := client.SuggestNow()
				select {
				case <-loopCtx.Done():
				case events <- SuggestionTickResult{Suggestion: sug, Err: err, OnDemand: true}:
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
			case consoleQueue <- consoleJob{line: c.Line}:
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
		case CmdGeneralizeAccept:
			job := consoleJob{gen: &genAcceptJob{list: c.List, pattern: c.Pattern, sources: c.Sources}}
			select {
			case consoleQueue <- job:
			default:
				select {
				case <-loopCtx.Done():
				case events <- ConsoleExecResult{Line: "generalize " + c.List + " " + c.Pattern, Output: "console busy: a prior command is still running\n"}:
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
// consoleJob is one unit of serialized work for the console worker:
// either a raw command line (Backend.Execute) or a structured
// generalize-accept (Backend.AcceptGeneralization). Routing structured
// data through the same single-worker channel keeps it serialized with
// console writes so two list mutations cannot race the configwrite
// rename (#173).
type consoleJob struct {
	line string
	gen  *genAcceptJob
}

type genAcceptJob struct {
	list    string
	pattern string
	sources []string
}

func consoleWorker(ctx context.Context, backend *console.Backend, in <-chan consoleJob, events chan<- Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-in:
			if !ok {
				return
			}
			var (
				line string
				out  string
				quit bool
			)
			if job.gen != nil {
				line = "generalize " + job.gen.list + " " + job.gen.pattern
				out = safeAccept(backend, job.gen)
			} else {
				line = job.line
				out, quit = safeExecute(backend, job.line)
			}
			select {
			case <-ctx.Done():
				return
			case events <- ConsoleExecResult{Line: line, Output: out, Quit: quit}:
			}
		}
	}
}

func safeAccept(backend *console.Backend, gen *genAcceptJob) (output string) {
	defer func() {
		if r := recover(); r != nil {
			output += fmt.Sprintf("panic: %v\n", r)
		}
	}()
	if backend == nil {
		return ""
	}
	var buf bytes.Buffer
	backend.AcceptGeneralization(&buf, gen.list, gen.pattern, gen.sources)
	return buf.String()
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
			case b == 0x0c: // Ctrl-L (hard repaint, #115)
				sendKey(ctx, events, KeyEvent{Key: KeyCtrlL})
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
				// Scan a full CSI sequence (`ESC [ <params> <final>`)
				// rather than special-casing fixed lengths. The fixed-
				// length form leaked the tail of modifier sequences as
				// printable runes: Shift-Up is `ESC [ 1 ; 2 A`, and the
				// old parser consumed `ESC [ 1`, matched nothing, and
				// emitted `;`, `2`, `A` — the `2` opened the info panel
				// (#171). Collect param/intermediate bytes (0x20-0x3f)
				// until a final byte (0x40-0x7e), then interpret as a
				// whole; unknown sequences are swallowed, never leaked.
				if i+1 < n && buf[i+1] == '[' {
					j := i + 2
					for j < n && buf[j] >= 0x20 && buf[j] <= 0x3f {
						j++
					}
					if j < n && buf[j] >= 0x40 && buf[j] <= 0x7e {
						if ev, ok := csiKeyEvent(buf[i+2:j], buf[j]); ok {
							sendKey(ctx, events, ev)
						}
						i = j + 1
					} else {
						// No final byte in this buffer (unterminated or
						// split across reads): fall back to a lone Esc,
						// matching the prior behavior for a bare ESC.
						sendKey(ctx, events, KeyEvent{Key: KeyEsc})
						i++
					}
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

// csiKeyEvent maps a parsed CSI sequence (the bytes between `ESC [` and
// the final byte, plus the final byte) to a KeyEvent. ok=false means
// the sequence is recognized-but-ignored or unknown — the caller emits
// nothing, so no byte ever leaks as a printable rune. xterm encodes a
// modifier as the second `;`-separated parameter (Shift=2, Alt=3,
// Ctrl=5, …); only Shift is distinguished here, and every other
// modifier degrades to the plain arrow.
func csiKeyEvent(params []byte, final byte) (KeyEvent, bool) {
	shift := false
	if fields := strings.Split(string(params), ";"); len(fields) >= 2 {
		shift = fields[1] == "2"
	}
	switch final {
	case 'A':
		if shift {
			return KeyEvent{Key: KeyShiftUp}, true
		}
		return KeyEvent{Key: KeyUp}, true
	case 'B':
		if shift {
			return KeyEvent{Key: KeyShiftDown}, true
		}
		return KeyEvent{Key: KeyDown}, true
	case 'Z':
		// Shift-Tab as emitted by xterm/screen/tmux.
		return KeyEvent{Key: KeyShiftTab}, true
	case 'H':
		// `ESC [ H` — Home (#196).
		return KeyEvent{Key: KeyHome}, true
	case 'F':
		// `ESC [ F` — End (#196).
		return KeyEvent{Key: KeyEnd}, true
	case '~':
		head := ""
		if len(params) > 0 {
			head = strings.Split(string(params), ";")[0]
		}
		switch head {
		case "3":
			return KeyEvent{Key: KeyDelete}, true
		case "1", "7":
			// VT-style Home (`ESC [ 1 ~` / `ESC [ 7 ~`) — #196.
			return KeyEvent{Key: KeyHome}, true
		case "4", "8":
			// VT-style End (`ESC [ 4 ~` / `ESC [ 8 ~`) — #196.
			return KeyEvent{Key: KeyEnd}, true
		}
	}
	return KeyEvent{}, false
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
	emitReload := func() {
		st, err := client.ReloadStatus()
		select {
		case <-ctx.Done():
		case events <- ReloadTickResult{Status: st, Err: err}:
		}
	}
	emitSuggestion := func() {
		sug, err := client.ActiveSuggestion()
		select {
		case <-ctx.Done():
		case events <- SuggestionTickResult{Suggestion: sug, Err: err}:
		}
	}
	emitOpenMode := func() {
		// Poll open-mode state so the border/footer revert automatically
		// when the window lapses, even with no keypress (#209).
		active, until, err := client.OpenModeState()
		select {
		case <-ctx.Done():
		case events <- OpenModeResult{Active: active, Until: until, Err: err}:
		}
	}
	emitHolds()
	emitOps()
	emitReload()
	emitSuggestion()
	emitOpenMode()
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			go emitHolds()
			go emitOps()
			go emitReload()
			go emitSuggestion()
			go emitOpenMode()
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

// buildFrame returns the frame body for the current model — the
// rendered character grid without the leading clear-screen escape.
// Caller chooses how to emit it (full or delta) via writeFullFrame
// or writeDeltaFrame.
//
// The terminal is split horizontally: the upper half hosts the
// approvals pane, the lower half hosts the console pane. Each pane
// carries its own top + bottom border with embedded help; there is
// no separate global hint row. On terminals narrower than
// borderMinThreshold the renderer falls back to the no-border
// layout (header rows + content).
func buildFrame(m Model) string {
	var b strings.Builder
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
	return frame
}

// writeFullFrame emits a complete repaint: home + clear-screen,
// then the entire frame body. Used for the first paint, after an
// explicit CmdRepaint / suspend resume, and as the fallback path
// for writeDeltaFrame when the prior frame cannot be diffed
// safely (line count changed; prev is empty).
func writeFullFrame(out io.Writer, frame string) error {
	_, err := io.WriteString(out, "\x1b[H\x1b[2J"+frame)
	return err
}

// writeDeltaFrame emits only the lines that differ from prev,
// each prefixed with a cursor-positioning escape and suffixed
// with a clear-to-EOL escape. The delta path avoids the full-
// screen repaint that produced the per-tick TUI flicker reported
// in #202.
//
// Fallback to writeFullFrame when:
//   - prev is empty (first paint after a hard reset).
//   - prev and frame have different line counts (terminal resized
//     or structural layout change).
//
// Equal frames produce zero bytes written — the natural shape of
// "no model state has changed" against the prior render. Existing
// tests that drive `render` (the full-paint wrapper below) are
// untouched; the delta path is opt-in for the production loop.
func writeDeltaFrame(out io.Writer, frame, prev string) error {
	if prev == "" {
		return writeFullFrame(out, frame)
	}
	prevLines := strings.Split(prev, "\n")
	currLines := strings.Split(frame, "\n")
	if len(prevLines) != len(currLines) {
		return writeFullFrame(out, frame)
	}
	var b strings.Builder
	for i, line := range currLines {
		if line == prevLines[i] {
			continue
		}
		// Each rendered line ends with \r\n (bodyLine appends both);
		// strings.Split on \n leaves the \r at the end of `line`. If
		// we emitted the line as-is followed by \x1b[K, the trailing
		// \r would return the cursor to col 0 BEFORE \x1b[K fires —
		// wiping the line we just wrote. Strip it before emit.
		emitted := strings.TrimSuffix(line, "\r")
		// \x1b[<r>;1H = move cursor to row r (1-indexed), col 1.
		// \x1b[K    = clear from cursor to end of line (handles the
		// shorter-than-prev case if padding ever drops below width).
		fmt.Fprintf(&b, "\x1b[%d;1H%s\x1b[K", i+1, emitted)
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// render is the historical full-paint entry point used by every
// unit test under internal/tui/. Production code uses
// buildFrame + writeDeltaFrame to avoid the per-tick full repaint.
func render(out io.Writer, m Model) error {
	return writeFullFrame(out, buildFrame(m))
}

func renderApprovalsPane(b *strings.Builder, m Model, rows int) {
	focused := m.Focused == PaneApprovals
	// While the open-mode window is active (#209), the approvals-pane
	// chrome renders in amber instead of the focus color — a persistent
	// "all traffic is being allowed" signal.
	chromeCol := chromeColor(focused)
	if openActive(m, time.Now()) {
		chromeCol = colorOpenMode
	}
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
	label := formatPaneLabel(formatOpsPaneLabelText(len(displayed), pending, m.ReloadStatus.LastError != "", m.ReloadStatus.LastSource, m.ReloadStatus.FailingSources...), focused)
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
	b.WriteString(topBorderC(label, rightHint, m.Cols, chromeCol))

	// Body: rows - 1 top border - 1 bottom border - 1 status row.
	bodyLines := rows - 3
	if bodyLines < 1 {
		bodyLines = 1
	}
	inner := m.Cols - 2
	if inner < 1 {
		inner = 1
	}
	const methodW, countW, statusW, timeW = 7, 1, 11, 14
	urlW := inner - methodW - countW - statusW - timeW - 6 // 1 leading space + 4 column gaps + 1 trailing
	if urlW < 8 {
		urlW = 8
	}
	now := time.Now()

	// #185: the non-resolved tail of DisplayedOps renders as a card
	// pinned to the bottom of the pane (like the generalize/suggestion
	// card), so pending requests stay on screen no matter how many
	// resolved ops scroll above them. The resolved head scrolls
	// independently in the list region.
	split := opsPendingSplit(displayed)
	resolved := displayed[:split]
	pendingOps := displayed[split:]

	// Top card slot (above pending): a manual generalize card (modal)
	// wins; else the daemon's ambient quiet-moment suggestion (#172),
	// shown only when no hold is pending so it never competes with the
	// pending card / approve-deny. Each line is width-fit so nothing
	// renders off-screen (the #170 bug).
	var topCard []string
	switch {
	case m.GenCard != nil:
		topCard = formatGeneralizeCard(*m.GenCard, inner)
	case m.Suggestion != nil && len(m.Holds) == 0:
		topCard = formatSuggestionCard(*m.Suggestion, inner)
	}
	if max := bodyLines - 1; len(topCard) > max && max >= 0 {
		topCard = topCard[:max]
	}

	// Pending card budget: reserve one line for the resolved column
	// header; pending is the load-bearing content (#156/#175) so it
	// takes the remaining space when large.
	selRel := -1
	if m.Selected >= split {
		selRel = m.Selected - split
	}
	pendMax := bodyLines - len(topCard) - 1
	if pendMax < 0 {
		pendMax = 0
	}
	pendCard := formatPendingCard(pendingOps, selRel, methodW, urlW, statusW, inner, pendMax, now, m.TickCount, m.History)

	listLines := bodyLines - len(topCard) - len(pendCard)
	if listLines < 1 {
		listLines = 1
	}
	used := 0
	if len(displayed) == 0 {
		b.WriteString(bodyLineC(padRight(runeTrunc("  (no recent operations — waiting for traffic)", inner), inner), m.Cols, chromeCol))
		used++
	} else {
		colHeader := fmt.Sprintf(" %-*s %-*s %s %-*s %s",
			methodW, "METHOD", urlW, "URL", " ", statusW, "STATUS", "TIME")
		b.WriteString(bodyLineC(padRight(runeTrunc(colHeader, inner), inner), m.Cols, chromeCol))
		used++
		// Bottom-anchored scroll within the resolved head; the cursor
		// follows up into resolved when it is there, and the window
		// rests at the bottom while the cursor is in the pending card.
		dataRows := listLines - 1
		first := opsScrollOffset(m.Selected, dataRows, len(resolved))
		end := first + dataRows
		if end > len(resolved) {
			end = len(resolved)
		}
		for i := first; i < end; i++ {
			if used >= listLines {
				break
			}
			row := formatOpRow(resolved[i], methodW, urlW, statusW, now, m.TickCount, m.History)
			row = padRightVisible(row, inner)
			if i == m.Selected {
				row = "\x1b[7m" + row + "\x1b[0m"
			}
			b.WriteString(bodyLineC(row, m.Cols, chromeCol))
			used++
		}
	}
	for used < listLines {
		b.WriteString(bodyLineC(padRight("", inner), m.Cols, chromeCol))
		used++
	}
	for _, cr := range topCard {
		b.WriteString(bodyLineC(cr, m.Cols, chromeCol))
	}
	for _, cr := range pendCard {
		b.WriteString(bodyLineC(cr, m.Cols, chromeCol))
	}

	// Status row (lives inside the border, above the bottom border).
	// The quiet-moment suggestion now renders as a width-fit card in
	// the body slot above (#172), not as a single status row that could
	// truncate off-screen.
	switch {
	case m.LastErr != "":
		row := "\x1b[31m" + padRight(runeTrunc("error: "+m.LastErr, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLineC(row, m.Cols, chromeCol))
	case m.LastInfo != "":
		row := "\x1b[32m" + padRight(runeTrunc(m.LastInfo, inner), inner) + "\x1b[0m"
		b.WriteString(bodyLineC(row, m.Cols, chromeCol))
	default:
		b.WriteString(bodyLineC(padRight("", inner), m.Cols, chromeCol))
	}

	// Bottom border carries the keybindings on the right. While the
	// generalization card is modal (#170), a/d mean accept/decline —
	// reflect that so the border hint matches the live key effect.
	keys := "[o] open  [a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [z] suspend  [q] quit"
	if openActive(m, now) {
		// While open, advertise close (with remaining seconds) and that
		// `o` extends the window (#209).
		remain := int(time.Until(m.OpenUntil).Seconds())
		if remain < 0 {
			remain = 0
		}
		keys = fmt.Sprintf("[c] close (%ds)  [o] +extend  [a] approve  [d] deny  [jk] select  [r] refresh  [q] quit", remain)
	}
	if m.GenCard != nil {
		keys = "[a]ccept  [d]ecline  [tab] next axis  [esc] dismiss"
	}
	b.WriteString(bottomBorderC("", keys, m.Cols, chromeCol))
}

// formatGeneralizeCard renders the unified generalization candidate
// card (#170) shown in the operations pane. Returns inner-width,
// colorized content lines (the caller wraps each in the pane border).
// Every line is runeTrunc'd to inner so the accept/decline keys can
// never be pushed off the right edge — the literal #170 defect.
func formatGeneralizeCard(card GeneralizeCard, inner int) []string {
	c := card.Current()
	axis := fmt.Sprintf("%d/%d", card.AxisIndex+1, len(card.Candidates))
	raw := []string{
		fmt.Sprintf("generalize (%s)  axis %s", c.Axis, axis),
		"  pattern: " + c.SuggestedPattern,
		"  from: " + card.SourceDesc + "  →  " + c.List,
		"  [a]ccept  [d]ecline  [tab] next axis  [esc] dismiss",
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = "\x1b[36m" + padRight(runeTrunc(l, inner), inner) + "\x1b[0m"
	}
	return out
}

// formatSuggestionCard renders the daemon's quiet-moment suggestion
// (#168) as a width-fit card in the operations pane (#172), matching
// the manual generalize card's shape. Returns inner-width, cyan
// content lines (the caller wraps each in the pane border). Every line
// is runeTrunc'd so the accept/decline keys can never be pushed off
// the right edge. The suggestion is ambient, so it uses shift+a/shift+d
// (distinct from the modal a/d of the manual card) to avoid stealing
// approve/deny.
func formatSuggestionCard(s Suggestion, inner int) []string {
	axis := ""
	if s.AxesRemaining > 0 {
		axis = fmt.Sprintf("  axis 1/%d", s.AxesRemaining+1)
	}
	var raw []string
	if s.PatternName != "" {
		// Pattern-shaped suggestion (#203 follow-up). Render the
		// structured fields so the operator sees what they're
		// agreeing to without parsing the synthetic summary string.
		raw = append(raw, fmt.Sprintf("suggestion (pattern:%s)%s", s.PatternName, axis))
		header := "  rule: pattern=" + s.PatternName
		if s.PatternMethod != "" {
			header += "  method=" + s.PatternMethod
		}
		header += "  effect=" + s.List
		raw = append(raw, header)
		if len(s.PatternComponents) > 0 {
			keys := make([]string, 0, len(s.PatternComponents))
			for k := range s.PatternComponents {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var fixed strings.Builder
			fixed.WriteString("  fixed:")
			for _, k := range keys {
				v := s.PatternComponents[k]
				if v == "" {
					v = "\"\""
				}
				fmt.Fprintf(&fixed, " %s=%s", k, v)
			}
			raw = append(raw, fixed.String())
		}
		raw = append(raw, fmt.Sprintf("  sources: %d entries", len(s.SourceEntries)))
		raw = append(raw, "  why: "+s.Reason)
		raw = append(raw, "  → "+s.List+"    [shift+a]ccept  [shift+d]ecline  [shift+s]kip")
	} else {
		raw = []string{
			fmt.Sprintf("suggestion (%s)%s", s.Axis, axis),
			"  pattern: " + s.SuggestedPattern,
			"  why: " + s.Reason,
			"  → " + s.List + "    [shift+a]ccept  [shift+d]ecline  [shift+s]kip",
		}
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = "\x1b[36m" + padRight(runeTrunc(l, inner), inner) + "\x1b[0m"
	}
	return out
}

// formatPendingCard renders the non-resolved tail of DisplayedOps as a
// card pinned to the bottom of the operations pane (#185), mirroring
// the generalize/suggestion card slot. pendingOps is displayed[split:];
// selRel is the selected row's index within pendingOps, or -1 when the
// cursor is in the resolved list above. maxRows caps the card height
// (a divider header plus rows); when pendingOps overflows, the rows are
// windowed bottom-anchored (newest pending last, the idle-snap target)
// while keeping the selected row visible. Returns inner-width content
// lines — the caller wraps each in the pane border or writes it raw on
// the no-border path. Returns nil when nothing is pending or no space.
func formatPendingCard(pendingOps []DisplayedOp, selRel, methodW, urlW, statusW, inner, maxRows int, now time.Time, tickCount int, history DecisionHistorySource) []string {
	if len(pendingOps) == 0 || maxRows < 1 {
		return nil
	}
	var out []string
	dataRows := maxRows
	if maxRows >= 2 {
		// Divider header — fill the inner width with box-drawing dashes
		// so the pending region reads as a distinct floating card.
		hdr := fmt.Sprintf(" ── pending (%d) ", len(pendingOps))
		if pad := inner - len([]rune(hdr)); pad > 0 {
			hdr += strings.Repeat("─", pad)
		}
		out = append(out, "\x1b[1m"+runeTrunc(hdr, inner)+"\x1b[0m")
		dataRows = maxRows - 1
	}
	first := opsScrollOffset(selRel, dataRows, len(pendingOps))
	end := first + dataRows
	if end > len(pendingOps) {
		end = len(pendingOps)
	}
	for i := first; i < end; i++ {
		row := padRightVisible(formatOpRow(pendingOps[i], methodW, urlW, statusW, now, tickCount, history), inner)
		if i == selRel {
			row = "\x1b[7m" + row + "\x1b[0m"
		}
		out = append(out, row)
	}
	return out
}

// formatOpRow renders one approvals-pane row for op `o` with the
// given per-column widths. Both the bordered and no-border render
// paths call this — extracting the shared format prevents the
// drift the two render functions accumulated before (#142). The
// caller is responsible for outer padding (`padRightVisible` or
// `bodyLine`) and for the inverse-highlight wrap on the selected
// row; this helper produces only the column-formatted row content.
//
// `statusW` is the *byte* width passed to the `%-*s` verb that
// formats the colorized status cell; ANSI escapes inflate the
// byte length beyond the visible width, so the bordered path
// passes `statusW+8` (visible width plus typical ANSI overhead)
// while the no-border path passes `statusW` (visible width only)
// and relies on `padRightVisible` to fix outer padding.
func formatOpRow(o DisplayedOp, methodW, urlW, statusW int, now time.Time, tickCount int, history DecisionHistorySource) string {
	urlCell := runeTrunc(o.URL, urlW)
	urlCellPadded := padRight(urlCell, urlW)
	host := extractHostForStatusColor(o.URL)
	effect := deriveOperatorEffect(o.Status)
	// #197: render the status cell at exactly statusW visible
	// chars (ANSI bytes excluded). Pre-fix, runeTrunc operated on
	// the already-colorized cell — rune count includes ANSI escape
	// bytes, so the truncation cut INTO the escape sequence and
	// produced fragments like "\x1b[33mpendi…" that rendered as
	// "pendi…" — narrower than statusW, displacing the TIME column.
	// padRightVisible sizes the colored cell at exactly statusW
	// visible chars; the bordered-render `+8` byte buffer becomes
	// unnecessary.
	statusCell := colorizeStatusForRow(o.Status, host, effect, tickCount, history)
	statusCell = padRightVisible(statusCell, statusW)
	return fmt.Sprintf(" %-*s %s %s %s %s",
		methodW, runeTrunc(o.Method, methodW),
		colorizeURLForRow(urlCellPadded, o.URL),
		brailleCounter(o.Count),
		statusCell,
		formatOpTime(o.UpdatedAt, now),
	)
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
// When `reloadFailed` is true, a sibling `␇ reload failed` badge
// fires in the same red-bold style (closes #129) — the daemon's
// last hot-reload attempt errored and the running set diverges
// from the file on disk. Both badges can fire together.
// formatPaneLabel further wraps the result with the pane's focus
// styling.
// reloadStatusForBadge captures the data the badge needs without
// pulling reloadstatus.Status into the format-function's signature.
// failingSources is non-nil when multiple sources are simultaneously
// failing (#165); the legacy reloadSource + reloadFailed pair
// remains so single-source render still works for callers that
// don't have the multi-source surface yet.
func formatOpsPaneLabelText(total, pending int, reloadFailed bool, reloadSource string, failingSources ...string) string {
	label := fmt.Sprintf("trollbridge operations — %d total · %d pending", total, pending)
	if pending > 0 {
		// \x1b[1;31m = bold red. The bell-glyph prefix doubles as a
		// no-color affordance for terminals that strip ANSI.
		label = fmt.Sprintf("trollbridge operations — %d total · \x1b[1;31m␇ %d pending\x1b[22;39m", total, pending)
	}
	// Multi-source path (#165): when the Tracker reports several
	// simultaneously-failing sources, stack one badge per source so
	// the operator triages from the badge alone instead of opening
	// the oplog. The list is pre-sorted by the Tracker.
	if len(failingSources) > 1 {
		for _, src := range failingSources {
			label += fmt.Sprintf(" · \x1b[1;31m␇ %s reload failed\x1b[22;39m", src)
		}
		return label
	}
	if reloadFailed {
		// Single-source path: embed the failing source name when
		// known so the operator can triage without digging into the
		// oplog (#145). Falls back to the bare badge for legacy
		// call paths or when the Tracker did not record a source.
		switch reloadSource {
		case "config", "rules", "lists":
			label += fmt.Sprintf(" · \x1b[1;31m␇ %s reload failed\x1b[22;39m", reloadSource)
		default:
			label += " · \x1b[1;31m␇ reload failed\x1b[22;39m"
		}
	}
	return label
}

// colorizeStatus wraps the status in a class color per #57's
// vocabulary: green for running/2xx, magenta for LLM-checking
// (#192), yellow for human-pending/signaled, red for denied/
// error/4xx/5xx, cyan for 3xx. Unknown statuses pass through
// uncolored. The "denied" and "signaled" tokens replace the
// trollbridge-internal 470/471 wire codes per #71.
//
// Per-status color only — animation and reversal wrap live in
// colorizeStatusForRow, the row-context variant.
func colorizeStatus(status string) string {
	color := ""
	switch status {
	case opstream.StatusRunning:
		color = "\x1b[32m"
	case opstream.StatusChecking:
		// #192: LLM-processing has its own color so the operator can
		// tell at a glance whether they are blocking (Pending) or the
		// LLM is (Checking).
		color = "\x1b[35m"
	case opstream.StatusPending, opstream.StatusSignaled:
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

// DecisionHistorySource is the small read-only surface
// colorizeStatusForRow consults to detect decision reversals
// (closes #192). The implementation lives in the daemon (a thin
// adapter over policy.History) and is wired through tui.Options
// for the in-process client; attach mode passes nil.
type DecisionHistorySource interface {
	// PriorOppositeEffect reports whether the given host has a
	// recent recorded decision whose effect differs from
	// currentEffect. currentEffect is "allow" or "deny"; an empty
	// string returns false (no current effect → nothing to compare).
	PriorOppositeEffect(host, currentEffect string) bool
}

// reversalWrap is the ANSI 256-color escape used to mark a row
// whose current decision contradicts a recent prior decision on
// the same host (closes #192). Bright orange (color 208) reads
// as a warning without the harshness of red and is distinct from
// every existing palette entry.
const reversalWrap = "\x1b[38;5;208m"

// colorizeStatusForRow renders the status cell with all #192
// affordances applied:
//
//   - StatusChecking gets the magenta per-status color plus a
//     cycling spinner glyph prefixed before the status word; the
//     glyph index is `tickCount % len(spinnerFrames)`.
//   - Resolved rows (HTTP code or StatusDenied) with effect != ""
//     are looked up against history; on opposite-effect prior
//     decision, the colorized cell is wrapped in the reversal
//     color before the trailing reset. The per-status color stays
//     inside the wrap so the operator still sees what the decision
//     was — the wrap signals "this contradicts a prior call."
//   - All other status classes pass through colorizeStatus
//     unchanged.
//
// history may be nil (attach mode); reversal coloring then
// degrades to off. effect is "allow", "deny", or "" (the caller
// derives it from status — see deriveOperatorEffect).
func colorizeStatusForRow(status, host, effect string, tickCount int, history DecisionHistorySource) string {
	if status == opstream.StatusChecking {
		// #192 reopen: previous animation advanced one frame per
		// ops tick (~1.5s), too subtle and too slow per operator
		// feedback. Replaced with ANSI blink (SGR 5) — terminal-
		// native, immediate, and unambiguous. Distinct glyph + the
		// more evocative term "thinking" (wire-format StatusChecking
		// is unchanged; this is a render-time substitution).
		_ = tickCount // animation no longer tick-driven
		return "\x1b[35;5m◌ thinking\x1b[0m"
	}
	colored := colorizeStatus(status)
	if effect != "" && history != nil && history.PriorOppositeEffect(host, effect) {
		// Wrap the colorized cell in the reversal color. The inner
		// per-status color stays so the operator still sees the
		// decision; the outer wrap signals the reversal.
		return reversalWrap + colored + "\x1b[0m"
	}
	return colored
}

// deriveOperatorEffect maps an op's Status to the operator effect
// the row represents, for reversal lookup (#192):
//
//   - "200"…"599"  → "allow" (operator allowed; upstream returned
//     that status)
//   - StatusDenied → "deny"
//   - everything else → "" (no clear operator effect — pre-
//     decision rows, transport errors, etc. — never trigger
//     reversal coloring)
//
// 4xx and 5xx codes are "allow" rather than "deny" because the
// operator approved the request and the upstream returned the
// non-2xx — that is not the operator's deny. Distinguishing
// rule-deny-emitted-4xx from upstream-emitted-4xx is out of
// scope (filed for future-state).
func deriveOperatorEffect(status string) string {
	if status == opstream.StatusDenied {
		return "deny"
	}
	if len(status) == 3 && status[0] >= '2' && status[0] <= '5' {
		return "allow"
	}
	return ""
}

// extractHostForStatusColor returns the host portion of a URL
// (without port) for reversal-history lookup (#192). It mirrors
// opGroupHostDir's host-extraction but strips the port so the
// result matches policy.History's `req.Host` field (which is
// the hostname only — port is stored separately). Pre-#192-
// reopen, this returned `host:port` and never matched the
// stored entries, so the reversal lookup silently returned
// false.
func extractHostForStatusColor(rawURL string) string {
	host, _ := opGroupHostDir(rawURL)
	// Strip the trailing :port for IPv4 and host. IPv6 bracketed
	// hosts come back from url.Parse as `[::1]:443`; the last `:`
	// before the port is preserved by SplitHostPort. Defensive:
	// if the split fails (no port), use the raw host.
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// Guard against IPv6 unbracketed: if there are multiple ':',
		// only strip when the part after the last ':' is all digits.
		port := host[i+1:]
		allDigits := port != ""
		for _, r := range port {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			host = host[:i]
		}
	}
	// Strip IPv6 brackets if present after port-stripping.
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return host
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
	header := formatOpsPaneLabelText(len(displayed), pending, m.ReloadStatus.LastError != "", m.ReloadStatus.LastSource, m.ReloadStatus.FailingSources...)
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
	const methodW, countW, statusW, timeW = 7, 1, 11, 14
	urlW := m.Cols - methodW - countW - statusW - timeW - 6
	if urlW < 8 {
		urlW = 8
	}
	now := time.Now()

	// #185: pin the pending tail to the bottom of the pane here too,
	// so the narrow-terminal fallback matches the bordered renderer.
	split := opsPendingSplit(displayed)
	resolved := displayed[:split]
	pendingOps := displayed[split:]
	selRel := -1
	if m.Selected >= split {
		selRel = m.Selected - split
	}
	pendMax := bodyLines - 1
	if pendMax < 0 {
		pendMax = 0
	}
	pendCard := formatPendingCard(pendingOps, selRel, methodW, urlW, statusW, m.Cols, pendMax, now, m.TickCount, m.History)
	listLines := bodyLines - len(pendCard)
	if listLines < 1 {
		listLines = 1
	}

	used := 0
	if len(displayed) == 0 {
		b.WriteString(padRight("  (no recent operations — waiting for traffic)", m.Cols))
		b.WriteString("\r\n")
		used++
	} else {
		colHeader := fmt.Sprintf(" %-*s %-*s %s %-*s %s",
			methodW, "METHOD", urlW, "URL", " ", statusW, "STATUS", "TIME")
		b.WriteString(padRight(colHeader, m.Cols))
		b.WriteString("\r\n")
		used++
		dataRows := listLines - 1
		first := opsScrollOffset(m.Selected, dataRows, len(resolved))
		end := first + dataRows
		if end > len(resolved) {
			end = len(resolved)
		}
		for i := first; i < end; i++ {
			if used >= listLines {
				break
			}
			row := formatOpRow(resolved[i], methodW, urlW, statusW, now, m.TickCount, m.History)
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
	for used < listLines {
		b.WriteString(padRight("", m.Cols))
		b.WriteString("\r\n")
		used++
	}
	for _, cr := range pendCard {
		b.WriteString(cr)
		b.WriteString("\r\n")
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

// llmDigestStartIndex returns the source-slice index from which the
// LLM panel renderers begin iterating (in newest-first display
// order). The default is len(m.Digests)-1 (newest first); when the
// selected digest sits below the visible newest-first window, the
// start index shifts so the selection stays on screen — anchor-at-
// bottom (#117).
//
// bodyLines is the panel's body row budget; the rough digest budget
// subtracts the extra rows the expanded selection consumes
// (DigestExpanded ⇒ multi-line detail block).
//
// Returns the DISPLAY index in displayedDigests(m) where the
// renderer should start its FORWARD iteration. #198 reworked from
// returning a m.Digests chronological-reverse index to a
// display-order index so the sort-by-URL toggle works.
//
// Stateless: recomputed on every render from
// (DigestSelected, displayedDigests(m), bodyLines). No Model field
// tracks scroll position. Both renderLLMPane and
// renderLLMPaneNoBorder use this helper.
func llmDigestStartIndex(m Model, bodyLines int) int {
	displayed := displayedDigests(m)
	if len(displayed) == 0 {
		return -1
	}
	displayIdx := digestSelectedIndex(m)
	if displayIdx <= 0 {
		// No selection (-1), or selection is the first displayed
		// row (0). Either way, start from the top.
		return 0
	}
	// Approximate the digest budget given the expanded-detail rows.
	// The expanded selection still counts as one "digest slot" — the
	// extra rows beyond the first eat into the budget for peer
	// digests.
	extraExpandedRows := 0
	if m.DigestExpanded {
		extraExpandedRows = llmDetailLineCountFor(m) - 1
		if extraExpandedRows < 0 {
			extraExpandedRows = 0
		}
	}
	digestBudget := bodyLines - extraExpandedRows
	if digestBudget < 1 {
		digestBudget = 1
	}
	start := displayIdx - digestBudget + 1
	if start < 0 {
		start = 0
	}
	return start
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
	displayed := displayedDigests(m)
	if len(displayed) == 0 {
		writeLine("(no LLM evaluations yet — advisor disabled or no traffic)", false)
	} else {
		// #198: iterate displayedDigests forward from the start
		// index (start is a DISPLAY index, not a m.Digests index).
		for i := llmDigestStartIndex(m, bodyLines); i >= 0 && i < len(displayed) && used < bodyLines; i++ {
			d := displayed[i]
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
	// No-border path uses the full row budget for the body (no
	// chrome border rows to subtract). The same scroll-offset rule
	// applies (#117). #198: iterate displayedDigests forward.
	displayed := displayedDigests(m)
	for i := llmDigestStartIndex(m, rows); i >= 0 && i < len(displayed) && used < rows; i++ {
		d := displayed[i]
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
	marked   bool // within the shift-select multi-selection range (#170)
}

// inGeneralizeSelection reports whether combined-list index idx is
// inside the active shift-select range (#170). False when no
// multi-selection is in progress.
func inGeneralizeSelection(m Model, idx int) bool {
	if m.URLsAnchor < 0 {
		return false
	}
	lo, hi := m.URLsAnchor, m.URLsSelected
	if lo > hi {
		lo, hi = hi, lo
	}
	return idx >= lo && idx <= hi
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
			lines = append(lines, urlsLine{text: "    " + p, selected: m.URLsSelected == i, marked: inGeneralizeSelection(m, i)})
		}
	}
	lines = append(lines, urlsLine{text: fmt.Sprintf("  DENY (%d)", len(m.DenyList))})
	if len(m.DenyList) == 0 {
		lines = append(lines, urlsLine{text: "    (empty)"})
	} else {
		allowLen := len(m.AllowList)
		for i, p := range m.DenyList {
			lines = append(lines, urlsLine{text: "    " + p, selected: m.URLsSelected == allowLen+i, marked: inGeneralizeSelection(m, allowLen+i)})
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

// opsScrollOffset returns the index of the first visible operations-pane
// row given the cursor, the number of op rows available, and the total
// op count (#175). Bottom-anchored: by default the last `rows` entries
// are shown, so the pending region — always at the tail of DisplayedOps
// (#156) — stays on screen. Scrolls UP to keep the cursor visible when
// the operator has navigated into the resolved region above the window.
// Distinct from urlsScrollOffset's centred rule: the ops pane biases to
// the bottom because pending is the load-bearing content.
func opsScrollOffset(cursor, rows, total int) int {
	if rows <= 0 || total <= rows {
		return 0
	}
	first := total - rows // bottom-anchored: pending at the tail stays visible
	if cursor >= 0 && cursor < first {
		first = cursor // follow the cursor up into the resolved region
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
	writeRow := func(text string, selected, marked bool) {
		if used >= bodyLines {
			return
		}
		cell := padRight(runeTrunc(text, inner), inner)
		if selected {
			cell = "\x1b[7m" + cell + "\x1b[0m"
		} else if marked {
			// Shift-select range member (#170): dim so the operator
			// sees what `g` will consume.
			cell = "\x1b[2m" + cell + "\x1b[0m"
		}
		b.WriteString(bodyLine(cell, m.Cols, focused))
		used++
	}

	if !m.URLsLocal {
		writeRow("  (allow/deny editing runs on the proxy host — open `trollbridge run` there)", false, false)
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
			writeRow(lines[i].text, lines[i].selected, lines[i].marked)
		}
	}
	for used < bodyLines {
		b.WriteString(bodyLine(padRight("", inner), m.Cols, focused))
		used++
	}
	urlsHint := "[jk] nav  [a/d] approve/deny  [+] add  [e] edit  [g] generalize  [s] suggest  [del] rm  [^z] undo"
	b.WriteString(bottomBorder(urlsHint, panelSwitcherHint, m.Cols, focused))
}

// renderURLsPaneNoBorder is the narrow-terminal fallback.
func renderURLsPaneNoBorder(b *strings.Builder, m Model, rows int) {
	panelHeaderLine(b, m, "── urls ── [jk] nav  [a/d] approve/deny  [+] add  [e] edit  [g] generalize  [s] suggest  [del] rm  [^z] undo ")
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
		} else if lines[i].marked {
			b.WriteString("\x1b[2m")
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
