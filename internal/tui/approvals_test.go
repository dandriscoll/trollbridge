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

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/console"
)

type stubClient struct {
	mu         sync.Mutex
	listFn     func() ([]approvals.Snapshot, error)
	approveErr error
	denyErr    error
	approveIDs []string
	denyIDs    []string
}

func (s *stubClient) ListHolds() ([]approvals.Snapshot, error) {
	s.mu.Lock()
	fn := s.listFn
	s.mu.Unlock()
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
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 100, 30, "")
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
	if !strings.Contains(stdout.String(), "trollbridge approvals") {
		t.Errorf("stdout missing approvals header; first 200: %q", first(stdout.String(), 200))
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
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 80, 24, "")
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
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "")
	}()

	time.Sleep(60 * time.Millisecond)
	// Tab → focus console.
	if _, err := pw.Write([]byte{'\t'}); err != nil {
		t.Fatalf("write tab: %v", err)
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
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, welcome)
	}()
	time.Sleep(80 * time.Millisecond)
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
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: false}, pr, &stdout, nil, 100, 30, "")
	}()
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

	if !strings.Contains(stdout.String(), "type `help`") {
		t.Errorf("default start hint missing; first 400: %q", first(stdout.String(), 400))
	}
}

// TestRunLoop_TabFlipsConsoleHeaderToBold verifies the rendered
// console-pane header is bold when focused (after Tab) — the focus
// indicator lives in ANSI escapes only.
func TestRunLoop_TabFlipsConsoleHeaderToBold(t *testing.T) {
	client := &stubClient{listFn: func() ([]approvals.Snapshot, error) { return nil, nil }}
	pr, pw := io.Pipe()
	var stdout strings.Builder

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, client, &console.Backend{LocalOnly: true}, pr, &stdout, nil, 100, 30, "")
	}()
	time.Sleep(60 * time.Millisecond)
	_, _ = pw.Write([]byte{'\t'})
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
	// After Tab, the console header is rendered with the bold ANSI
	// escape `\x1b[1m`; the approvals header is dim `\x1b[2m`. We
	// look for the bold escape immediately preceding "console".
	if !strings.Contains(out, "\x1b[1m"+"console") {
		t.Errorf("console header not bold after Tab; first 400: %q", first(out, 400))
	}
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
