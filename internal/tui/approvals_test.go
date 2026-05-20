package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/opstream"
	"github.com/dandriscoll/trollbridge/internal/reloadstatus"
	"github.com/dandriscoll/trollbridge/internal/types"
)

type stubClient struct {
	mu         sync.Mutex
	listFn     func() ([]approvals.Snapshot, error)
	opsFn      func() ([]opstream.Op, error)
	approveErr error
	denyErr    error
	approveIDs []string
	denyIDs    []string
	suggestion *Suggestion
	acceptedID []string
	declinedID []string
}

func (s *stubClient) ListHolds() ([]approvals.Snapshot, error) {
	s.mu.Lock()
	fn := s.listFn
	s.mu.Unlock()
	return fn()
}

func (s *stubClient) RecentOps() ([]opstream.Op, error) {
	s.mu.Lock()
	fn := s.opsFn
	s.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	return fn()
}

func (s *stubClient) Approve(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approveIDs = append(s.approveIDs, id)
	return s.approveErr
}

func (s *stubClient) Deny(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyIDs = append(s.denyIDs, id)
	return s.denyErr
}

func (s *stubClient) RecentLLMDigests() ([]advisor.Digest, error) {
	return nil, nil
}

func (s *stubClient) RecentURLs() ([]string, []string, bool, error) {
	return nil, nil, false, nil
}

func (s *stubClient) ReloadStatus() (reloadstatus.Status, error) {
	return reloadstatus.Status{}, nil
}

func (s *stubClient) ActiveSuggestion() (*Suggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suggestion, nil
}

func (s *stubClient) AcceptSuggestion(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedID = append(s.acceptedID, id)
	return nil
}

func (s *stubClient) DeclineSuggestion(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.declinedID = append(s.declinedID, id)
	return nil
}

// TestRunLoop_ApproveFlowEndToEnd drives runLoop with scripted
// keystrokes and a stub control client; asserts the approve call
// landed and the loop exited cleanly on 'q'.
func TestRunLoop_ApproveFlowEndToEnd(t *testing.T) {
	holds := []approvals.Snapshot{
		{ID: "hold-1", Host: "api.example.com", Port: 443, Path: "/v1/x", IdentityID: "agent-a"},
	}
	var listCount atomic.Int32
	client := &stubClient{
		listFn: func() ([]approvals.Snapshot, error) {
			listCount.Add(1)
			return holds, nil
		},
	}

	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for listCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if listCount.Load() == 0 {
		t.Fatalf("ListHolds was never called")
	}
	time.Sleep(50 * time.Millisecond)

	if _, err := pw.Write([]byte{'a'}); err != nil {
		t.Fatalf("write a: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := pw.Write([]byte{'q'}); err != nil {
		t.Fatalf("write q: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v, want nil", err)
		}
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit before deadline")
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.approveIDs) != 1 || client.approveIDs[0] != "hold-1" {
		t.Errorf("approveIDs = %v, want [hold-1]", client.approveIDs)
	}
	if len(client.denyIDs) != 0 {
		t.Errorf("denyIDs = %v, want none", client.denyIDs)
	}
	if !strings.Contains(stdout.String(), "trollbridge operations") {
		t.Errorf("stdout missing operations header; first 200: %q", first(stdout.String(), 200))
	}
	if !strings.Contains(stdout.String(), "console") {
		t.Errorf("stdout missing console pane header; first 200: %q", first(stdout.String(), 200))
	}
}

// TestRunLoop_QuitOnCtxCancel ensures the loop honors parent ctx.
func TestRunLoop_QuitOnCtxCancel(t *testing.T) {
	client := &stubClient{
		listFn: func() ([]approvals.Snapshot, error) { return nil, errors.New("stub") },
	}
	pr, _ := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 80, 24, "", nil, DefaultOptions())
	}()

	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("runLoop did not exit on ctx cancel")
	}
}

// TestRunLoop_TabSwitchesFocusAndConsoleExecutes proves Tab moves
// focus to the console pane, typed input lands in the input buffer,
// and Enter triggers Backend.Execute. We use the help command (which
// is local-only-agnostic) so the assertion is pure-output.
func TestRunLoop_TabSwitchesFocusAndConsoleExecutes(t *testing.T) {
	client := &stubClient{
		listFn: func() ([]approvals.Snapshot, error) { return nil, nil },
	}
	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()

	time.Sleep(60 * time.Millisecond)
	// '1' opens the console panel AND auto-focuses it (#77).
	if _, err := pw.Write([]byte("1")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	// Type "help\n".
	if _, err := pw.Write([]byte("help\n")); err != nil {
		t.Fatalf("write help: %v", err)
	}
	time.Sleep(120 * time.Millisecond)
	// Type "quit\n" — the backend asks the loop to exit.
	if _, err := pw.Write([]byte("quit\n")); err != nil {
		t.Fatalf("write quit: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v, want nil", err)
		}
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit before deadline")
	}

	out := stdout.String()
	// The help command echoes its command list into the console pane's
	// scrollback; render() draws that scrollback.
	for _, want := range []string{"allow", "deny", "list"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing help text %q in render; first 400: %q", want, first(out, 400))
		}
	}
}

// TestRunLoop_WelcomeAppearsInScrollback verifies the welcome string
// (used for the run startup banner) lands in the console pane's
// rendered output.
func TestRunLoop_WelcomeAppearsInScrollback(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	welcome := "trollbridge is listening on 127.0.0.1:8080 (mode: default-deny).\n"
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, welcome, nil, DefaultOptions())
	}()
	time.Sleep(60 * time.Millisecond)
	// '1' opens the console panel where the welcome lives.
	_, _ = pw.Write([]byte("1"))
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03}) // Ctrl-C

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit before deadline")
	}

	out := stdout.String()
	if !strings.Contains(out, "127.0.0.1:8080") {
		t.Errorf("welcome content missing from rendered output; first 400: %q", first(out, 400))
	}
}

// TestRunLoop_DefaultStartHintWhenNoWelcome verifies the empty-welcome
// path leaves a "type help" hint in scrollback.
func TestRunLoop_DefaultStartHintWhenNoWelcome(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()
	time.Sleep(60 * time.Millisecond)
	// '1' opens the console panel where the start hint lives.
	_, _ = pw.Write([]byte("1"))
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit before deadline")
	}

	if !strings.Contains(stdout.String(), "type `help`") {
		t.Errorf("default start hint missing; first 400: %q", first(stdout.String(), 400))
	}
}

// TestRunLoop_ConsoleHotkeyAutoFocusesBorderCyan verifies that the
// rendered console-pane top border is cyan as soon as '1' opens
// the panel — pressing '1' now both opens AND focuses the console
// (closes #77). The focus signal is the bright-cyan border color
// (\x1b[36m) on the border row that contains the pane label.
func TestRunLoop_ConsoleHotkeyAutoFocusesBorderCyan(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()
	time.Sleep(60 * time.Millisecond)
	// '1' opens the console panel AND auto-focuses it.
	_, _ = pw.Write([]byte("1"))
	time.Sleep(80 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoop returned %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit before deadline")
	}

	out := stdout.String()
	rows := strings.Split(out, "\r\n")
	var consoleRow string
	for _, row := range rows {
		if strings.Contains(row, "console") && strings.Contains(row, "╭") {
			consoleRow = row // keep last match — the post-'1' frame
		}
	}
	if consoleRow == "" {
		t.Fatalf("no console top-border row found in output; first 400: %q", first(out, 400))
	}
	if !strings.Contains(consoleRow, "\x1b[36m") {
		t.Errorf("console top border not cyan-focused after '1' (auto-focus); row: %q", consoleRow)
	}
}

// TestRender_TabHintAppearsInFocusedPaneTopBorder pins the #41 fix:
// the [Tab] focus <pane> cue lives in the focused pane's top border
// at top-right, naming the pane Tab will focus TO. When approvals is
// focused the cue reads "focus console" on the approvals pane's top
// border; when console is focused it reads "focus approvals" on the
// console pane's top border.
func TestRender_TabHintAppearsInFocusedPaneTopBorder(t *testing.T) {
	t.Run("approvals focused → cue on approvals top border", func(t *testing.T) {
		client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
		pr, pw := io.Pipe()
		var stdout strings.Builder
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
		}()
		time.Sleep(60 * time.Millisecond)
		// '1' opens the console panel AND auto-focuses it (#77), so
		// to assert the approvals-focused cue we Tab back to approvals.
		_, _ = pw.Write([]byte("1"))
		time.Sleep(60 * time.Millisecond)
		_, _ = pw.Write([]byte{'\t'}) // flip focus back to approvals
		time.Sleep(60 * time.Millisecond)
		_, _ = pw.Write([]byte{0x03})
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatalf("runLoop did not exit")
		}
		out := stdout.String()
		if !strings.Contains(out, "[Tab] focus console") {
			t.Errorf("cue missing 'focus console'; first 600: %q", first(out, 600))
		}
		// The cue must live on the same row as the upper pane top
		// border (corners ╭ and ╮) — i.e. in the top border itself, not
		// on a separate global row.
		rows := strings.Split(out, "\r\n")
		found := false
		for _, row := range rows {
			if strings.Contains(row, "[Tab] focus console") &&
				strings.Contains(row, "╭") && strings.Contains(row, "╮") &&
				strings.Contains(row, "operations") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("'[Tab] focus console' cue not on approvals top-border row; output: %q", first(out, 800))
		}
	})
	t.Run("console focused → cue on console top border", func(t *testing.T) {
		client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
		pr, pw := io.Pipe()
		var stdout strings.Builder
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
		}()
		time.Sleep(60 * time.Millisecond)
		_, _ = pw.Write([]byte("1")) // open console panel; auto-focus puts focus on console (#77)
		time.Sleep(80 * time.Millisecond)
		_, _ = pw.Write([]byte{0x03})
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatalf("runLoop did not exit")
		}
		out := stdout.String()
		if !strings.Contains(out, "[Tab] focus approvals") {
			t.Errorf("cue missing 'focus approvals' after Tab; first 600: %q", first(out, 600))
		}
		rows := strings.Split(out, "\r\n")
		found := false
		for _, row := range rows {
			if strings.Contains(row, "[Tab] focus approvals") &&
				strings.Contains(row, "╭") && strings.Contains(row, "╮") &&
				strings.Contains(row, "console") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("'[Tab] focus approvals' cue not on console top-border row; output: %q", first(out, 800))
		}
	})
}

// TestRender_BottomBorderCarriesKeybindings asserts the per-pane
// keybinding hints live on the pane's bottom border (the row carrying
// ╰ and ╯), not on a separate footer row.
func TestRender_BottomBorderCarriesKeybindings(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte("1")) // open console panel so its bottom border renders (#66)
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit")
	}
	out := stdout.String()
	rows := strings.Split(out, "\r\n")

	approvalsBottomFound := false
	consoleBottomFound := false
	for _, row := range rows {
		if strings.Contains(row, "[a] approve") &&
			strings.Contains(row, "╰") && strings.Contains(row, "╯") {
			approvalsBottomFound = true
		}
		if strings.Contains(row, "[Ctrl-C] quit") &&
			strings.Contains(row, "╰") && strings.Contains(row, "╯") {
			consoleBottomFound = true
		}
	}
	if !approvalsBottomFound {
		t.Errorf("'[a] approve' not on approvals bottom-border row; output: %q", first(out, 1200))
	}
	if !consoleBottomFound {
		t.Errorf("'[Ctrl-C] quit' not on console bottom-border row; output: %q", first(out, 1200))
	}
}

// TestRender_GlobalHintRowDeleted confirms the prior global bottom
// hint row is gone. Its unique separator was "•  [Ctrl-C]" which only
// appeared on that one row; the [Ctrl-C] quit text now appears on the
// console pane's bottom border (without the • separator).
func TestRender_GlobalHintRowDeleted(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()
	time.Sleep(80 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit")
	}
	if strings.Contains(stdout.String(), "•  [Ctrl-C]") {
		t.Errorf("global hint row separator '•  [Ctrl-C]' still in output; should be deleted")
	}
}

// TestRender_BothPanesHaveBorders is the sweep test: each of the four
// rounded corner runes appears exactly twice — once per pane. Catches
// "we forgot the console pane's top border" (count=1) or "duplicated
// the approvals border" (count=3) regressions.
func TestRender_BothPanesHaveBorders(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "", nil, DefaultOptions())
	}()
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte("1")) // open console panel to get two-pane layout (#66)
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte{0x03})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("runLoop did not exit")
	}
	out := stdout.String()
	// Take only the LAST render frame: \x1b[H\x1b[2J clears the screen
	// each frame. Counting across all frames would conflate redraws.
	parts := strings.Split(out, "\x1b[H\x1b[2J")
	if len(parts) < 2 {
		t.Fatalf("no render frame found in output; first 400: %q", first(out, 400))
	}
	last := parts[len(parts)-1]
	for _, corner := range []string{"╭", "╮", "╰", "╯"} {
		if got := strings.Count(last, corner); got != 2 {
			t.Errorf("corner %q appears %d time(s) in last frame; want 2 (one per pane)",
				corner, got)
		}
	}
}

// TestRender_NoTrailingNewlineFitsScreen pins the #50 fix: a render
// frame must not end with a line terminator. With a trailing \n, the
// terminal cursor advances past the bottom row and the screen scrolls
// up by one line — dropping the top border off-screen and producing
// the visible "one line down, one line up" twitch in tmux at every
// 1.5 s refresh tick.
//
// The test drives render() directly (not runLoop) because the
// trailing-newline contract is a property of one frame; runLoop emits
// many concatenated frames.
func TestRender_NoTrailingNewlineFitsScreen(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows int
	}{
		{"24-row terminal", 24},
		{"30-row terminal", 30},
		{"40-row terminal", 40},
		{"odd row count", 31},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{
				Cols:    100,
				Rows:    tc.rows,
				Focused: PaneApprovals,
				Console: ConsoleModel{Prompt: "trollbridge> "},
			}
			var buf strings.Builder
			if err := render(&buf, m); err != nil {
				t.Fatalf("render: %v", err)
			}
			frame := buf.String()
			if strings.HasSuffix(frame, "\n") {
				t.Errorf("frame ends with a line terminator (would scroll the top row off-screen)")
			}
			// The frame should contain m.Rows-1 inter-line newlines (one
			// between each adjacent pair of rendered rows). Any other count
			// means the frame doesn't fit the screen.
			if got, want := strings.Count(frame, "\n"), tc.rows-1; got != want {
				t.Errorf("frame has %d newlines; want %d (m.Rows-1)", got, want)
			}
		})
	}
}

// TestInProcessClient_RoundtripsAgainstRealQueue closes the gap that
// ships the proxy-host wedge described in job 091: the embedded TUI
// in `trollbridge run` shares a process with the daemon and must be
// able to fetch / resolve holds without the mTLS controller-client
// cert. NewInProcessClient skips the cert hop; this test pins the
// contract by enqueueing a real hold and exercising every method on
// the ControlClient surface.
func TestInProcessClient_RoundtripsAgainstRealQueue(t *testing.T) {
	q := approvals.New(8, 5*time.Second, "deny")
	defer q.Shutdown()

	client := NewInProcessClient(q, nil)

	// Empty queue ⇒ empty list, no error.
	if got, err := client.ListHolds(); err != nil || len(got) != 0 {
		t.Fatalf("ListHolds() empty: got=%v err=%v, want []/nil", got, err)
	}

	// Enqueue one. The TUI fetches via Pending() under the hood.
	req := &types.RequestEvent{
		ID:         "req-1",
		IdentityID: "agent-x",
		Method:     "CONNECT",
		Scheme:     "https-tunneled",
		Host:       "api.example.com",
		Port:       443,
	}
	id, ch, err := q.Enqueue(req, types.Decision{Effect: types.EffectAskUser, Source: types.SourceDefault})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	holds, err := client.ListHolds()
	if err != nil {
		t.Fatalf("ListHolds: %v", err)
	}
	if len(holds) != 1 || holds[0].ID != id || holds[0].Host != "api.example.com" {
		t.Fatalf("ListHolds = %+v, want one hold with id=%s host=api.example.com", holds, id)
	}

	// Approve via the in-process client. The hold's resolve channel
	// must carry an allow decision afterwards.
	if err := client.Approve(id); err != nil {
		t.Fatalf("Approve(%s): %v", id, err)
	}
	select {
	case d := <-ch:
		if d.Effect != types.EffectAskUserResolvedAllow {
			t.Fatalf("decision after Approve = %v, want resolved_allow", d.Effect)
		}
		if d.Source != types.SourceApprovalQueue {
			t.Fatalf("decision source = %v, want approval_queue", d.Source)
		}
	case <-time.After(time.Second):
		t.Fatalf("no decision delivered after Approve")
	}

	// Approving a non-existent hold returns an error rather than
	// silently no-op'ing — the TUI footer surfaces the error.
	if err := client.Approve("hold-does-not-exist"); err == nil {
		t.Errorf("Approve(missing) returned nil, want error")
	}

	// Enqueue a second hold, deny it via the client, verify the
	// decision channel sees the deny + the operator's reason.
	req2 := &types.RequestEvent{ID: "req-2", IdentityID: "agent-y", Method: "GET", Host: "api.example.com", Port: 443}
	id2, ch2, err := q.Enqueue(req2, types.Decision{Effect: types.EffectAskUser, Source: types.SourceDefault})
	if err != nil {
		t.Fatalf("Enqueue(2): %v", err)
	}
	if err := client.Deny(id2, "blocked by policy"); err != nil {
		t.Fatalf("Deny(%s): %v", id2, err)
	}
	select {
	case d := <-ch2:
		if d.Effect != types.EffectAskUserResolvedDeny {
			t.Fatalf("decision after Deny = %v, want resolved_deny", d.Effect)
		}
		if d.Reason != "blocked by policy" {
			t.Fatalf("deny reason = %q, want %q", d.Reason, "blocked by policy")
		}
	case <-time.After(time.Second):
		t.Fatalf("no decision delivered after Deny")
	}

	if err := client.Deny("hold-does-not-exist", "reason"); err == nil {
		t.Errorf("Deny(missing) returned nil, want error")
	}
}

// TestInProcessClient_NilQueue covers the defensive path: an
// uninitialized client (caller bug) returns errors instead of
// nil-deref panics.
func TestInProcessClient_NilQueue(t *testing.T) {
	client := NewInProcessClient(nil, nil)
	if _, err := client.ListHolds(); err == nil {
		t.Errorf("ListHolds() with nil queue: want error, got nil")
	}
	if err := client.Approve("any"); err == nil {
		t.Errorf("Approve() with nil queue: want error, got nil")
	}
	if err := client.Deny("any", "any"); err == nil {
		t.Errorf("Deny() with nil queue: want error, got nil")
	}
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// TestFormatOpRow_StructureAndContent locks the column structure of
// the shared formatOpRow helper (#142). Both renderApprovalsPane and
// renderApprovalsPaneNoBorder call this helper; a regression that
// drops, reorders, or swaps a column fails this test before the
// visual render tests do.
func TestFormatOpRow_StructureAndContent(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	op := DisplayedOp{
		Op: opstream.Op{
			Method:    "GET",
			URL:       "https://example.com/path",
			Status:    "200",
			UpdatedAt: now.Add(-2 * time.Second),
		},
		Count: 1,
	}
	row := formatOpRow(op, 7, 30, 11, now)
	if !strings.Contains(row, "GET") {
		t.Errorf("missing method; row=%q", row)
	}
	if !strings.Contains(row, "example.com/path") {
		t.Errorf("missing URL; row=%q", row)
	}
	if !strings.Contains(row, "200") {
		t.Errorf("missing status code 200; row=%q", row)
	}
	mi := strings.Index(row, "GET")
	ui := strings.Index(row, "example.com")
	si := strings.Index(row, "200")
	if !(mi < ui && ui < si) {
		t.Errorf("column ordering broken: method=%d url=%d status=%d row=%q", mi, ui, si, row)
	}
}
