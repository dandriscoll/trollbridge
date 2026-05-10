package server

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestOps_RecordsAllowedRequestWithHTTPCode pins the #52 contract on
// the daemon side: a successful proxied request lands in the ops
// ring, keyed by request_id, with status set to the upstream HTTP
// status code (here "200").
func TestOps_RecordsAllowedRequestWithHTTPCode(t *testing.T) {
	origin, originURL := plainOrigin(t, "hello")
	originHost := strings.TrimPrefix(originURL, "http://")
	originHostOnly, _, _ := net.SplitHostPort(originHost)

	rules := fmt.Sprintf(`
- id: allow-origin
  match: {host: %s}
  effect: allow
`, originHostOnly)
	h := bootProxy(t, "default-deny", rules)
	defer h.close()

	// Capture the ring before close() shuts the harness down.
	ring := h.srv.Ops()

	c := h.clientThroughProxy()
	resp, err := c.Get(origin.URL + "/things")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Give the audit-write hook time to fire (it runs synchronously
	// on the same goroutine as the response, but the request
	// goroutine may still be wrapping up — give it 250 ms).
	deadline := time.Now().Add(250 * time.Millisecond)
	var snap []opstream.Op
	for time.Now().Before(deadline) {
		snap = ring.Snapshot()
		if len(snap) > 0 && snap[0].Status == "200" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(snap) == 0 {
		t.Fatalf("ops ring empty after request")
	}
	op := snap[0]
	if op.Method != "GET" {
		t.Errorf("op.Method = %q, want GET", op.Method)
	}
	if !strings.Contains(op.URL, "/things") {
		t.Errorf("op.URL = %q, want it to include /things", op.URL)
	}
	if op.Status != "200" {
		t.Errorf("op.Status = %q, want 200", op.Status)
	}
	if op.RequestID == "" {
		t.Errorf("op.RequestID is empty")
	}
}

// TestOps_RecordsDeniedRequest pins that a request the engine denies
// shows up in the ring with status "denied" — not the HTTP status
// the client sees (which is StatusTrollbridgeDeclined).
func TestOps_RecordsDeniedRequest(t *testing.T) {
	_, originURL := plainOrigin(t, "shouldnotreach")
	h := bootProxy(t, "default-deny", `
- id: never
  match: {host: "never.match.example"}
  effect: allow
`)
	defer h.close()
	ring := h.srv.Ops()

	c := h.clientThroughProxy()
	resp, _ := c.Get(originURL)
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	var snap []opstream.Op
	for time.Now().Before(deadline) {
		snap = ring.Snapshot()
		if len(snap) > 0 && snap[0].Status == opstream.StatusDenied {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(snap) == 0 {
		t.Fatalf("ops ring empty after denied request")
	}
	if snap[0].Status != opstream.StatusDenied {
		t.Errorf("op.Status = %q, want %q", snap[0].Status, opstream.StatusDenied)
	}
}
