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

	"github.com/dandriscoll/drawbridge/internal/approvals"
)

type stubClient struct {
	mu          sync.Mutex
	listFn      func() ([]approvals.Snapshot, error)
	approveErr  error
	denyErr     error
	approveIDs  []string
	denyIDs     []string
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

// TestRunLoop_ApproveFlowEndToEnd drives the inner runLoop with
// scripted keystrokes and a stub control client; asserts the
// approve call landed and the loop exited cleanly on 'q'.
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
		done <- runLoop(ctx, client, pr, &stdout, nil, 100, 30)
	}()

	// Wait for at least one tick so holds populate.
	deadline := time.Now().Add(2 * time.Second)
	for listCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if listCount.Load() == 0 {
		t.Fatalf("ListHolds was never called")
	}

	// Brief pause so the TickResult is processed.
	time.Sleep(50 * time.Millisecond)

	// Approve, then quit.
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
	if !strings.Contains(stdout.String(), "drawbridge approvals") {
		t.Errorf("stdout missing header; first 200: %q", first(stdout.String(), 200))
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
		done <- runLoop(ctx, client, pr, &stdout, nil, 80, 24)
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

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
