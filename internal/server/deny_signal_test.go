package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Job 054 — assert that the response signal trollbridge sends on
// deny includes Trollbridge-Request-Id, Proxy-Status (RFC 9209),
// and a content-negotiated body. Exercises the HTTP path; CONNECT
// and intercepted-HTTPS are covered in their own existing tests
// after the same shape was added there.

func TestDenySignal_HTTPCarriesAllHeaders(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))

	rules := `
- id: deny-origin
  match: {host: ` + originHostOnly + `}
  effect: deny
`
	h := bootProxy(t, "default-allow", rules)

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}
	rid := resp.Header.Get(HeaderRequestID)
	if rid == "" {
		t.Error("missing Trollbridge-Request-Id header")
	}
	if reason := resp.Header.Get(HeaderReason); !strings.HasPrefix(reason, "deny:") {
		t.Errorf("Trollbridge-Reason: got %q", reason)
	}
	ps := resp.Header.Get(HeaderProxyStatus)
	if !strings.HasPrefix(ps, "trollbridge;") {
		t.Errorf("Proxy-Status missing or wrong shape: %q", ps)
	}
	if !strings.Contains(ps, `error=http_request_denied`) {
		t.Errorf("Proxy-Status missing http_request_denied token: %q", ps)
	}
	if !strings.Contains(ps, `request-id="`+rid+`"`) {
		t.Errorf("Proxy-Status request-id mismatch: header=%q want %q", ps, rid)
	}
	if !strings.Contains(ps, `details="rule deny-origin:`) {
		t.Errorf("Proxy-Status details should prefix rule id when SourceRule: %q", ps)
	}
	// Default Accept (Go's http.Client sends none unless set) gets plain text.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q want text/plain*", ct)
	}
	if !strings.Contains(string(body), "request denied") {
		t.Errorf("plain body unexpected: %q", body)
	}

	// Audit must carry the same request_id.
	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	last := entries[len(entries)-1]
	if last.RequestID != rid {
		t.Errorf("audit request_id mismatch: header=%s audit=%s", rid, last.RequestID)
	}
	if last.RuleID != "deny-origin" {
		t.Errorf("audit rule_id: got %q want deny-origin", last.RuleID)
	}
}

func TestDenySignal_HTTPJSONBodyOnAcceptHeader(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))
	rules := `
- id: deny-origin-json
  match: {host: ` + originHostOnly + `}
  effect: deny
`
	h := bootProxy(t, "default-allow", rules)

	c := h.clientThroughProxy()
	req, err := http.NewRequest("GET", originURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q want application/json", ct)
	}
	var rb refusalBody
	if err := json.Unmarshal(body, &rb); err != nil {
		t.Fatalf("body not JSON: %v: %s", err, body)
	}
	if rb.Effect != "deny" {
		t.Errorf("effect: got %q", rb.Effect)
	}
	if rb.RuleID != "deny-origin-json" {
		t.Errorf("rule_id: got %q", rb.RuleID)
	}
	if rb.RequestID != resp.Header.Get(HeaderRequestID) {
		t.Errorf("request_id mismatch: body=%s header=%s", rb.RequestID, resp.Header.Get(HeaderRequestID))
	}
	if rb.Reason == "" {
		t.Error("reason should not be empty")
	}
	// Headers must still be present alongside JSON body.
	if resp.Header.Get(HeaderRequestID) == "" {
		t.Error("Trollbridge-Request-Id missing on JSON deny")
	}
	if resp.Header.Get(HeaderProxyStatus) == "" {
		t.Error("Proxy-Status missing on JSON deny")
	}
}

func TestAllowSignal_HTTPCarriesRequestID(t *testing.T) {
	_, originURL := plainOrigin(t, "ok")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))
	rules := `
- id: allow-origin
  match: {host: ` + originHostOnly + `}
  effect: allow
`
	h := bootProxy(t, "default-deny", rules)

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d", resp.StatusCode)
	}
	rid := resp.Header.Get(HeaderRequestID)
	if rid == "" {
		t.Fatal("Trollbridge-Request-Id missing on allow forward")
	}
	entries := h.auditEntries()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	last := entries[len(entries)-1]
	if last.RequestID != rid {
		t.Errorf("audit request_id mismatch: header=%s audit=%s", rid, last.RequestID)
	}
}

// TestDenySignal_CONNECTRawWireFormat dials the proxy at the
// TCP layer and writes a CONNECT request manually so it can read
// and parse the proxy's 403 response shape directly. Most HTTP
// client libraries discard CONNECT-failure response bodies and
// headers (the client-library opacity documented in AGENTS.md);
// this test asserts the signal is on the wire even though the
// majority of clients will not see it.
func TestDenySignal_CONNECTRawWireFormat(t *testing.T) {
	h := bootProxy(t, "default-deny", `
- id: nothing
  match: {host: never.match.example}
  effect: allow
`)

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", resp.StatusCode)
	}
	if rid := resp.Header.Get(HeaderRequestID); rid == "" {
		t.Error("Trollbridge-Request-Id missing on CONNECT-deny")
	}
	ps := resp.Header.Get(HeaderProxyStatus)
	if !strings.Contains(ps, "error=http_request_denied") {
		t.Errorf("Proxy-Status missing on CONNECT-deny: %q", ps)
	}
	if !resp.Close {
		t.Error("CONNECT-deny should signal Connection: close (resp.Close=true)")
	}

	// And the same id must reach the audit log.
	entries := h.auditEntries()
	rid := resp.Header.Get(HeaderRequestID)
	matched := false
	for _, e := range entries {
		if e.Method == "CONNECT" && e.Decision == "deny" && e.RequestID == rid {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("audit lacks a CONNECT-deny entry with request_id=%s", rid)
	}
}

func TestDenySignal_InlineListNoRulePrefix(t *testing.T) {
	_, originURL := plainOrigin(t, "x")
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(originURL, "http://"))
	h := bootProxy(t, "default-allow", "")
	if err := h.srv.SetLists(nil, []string{originHostOnly}); err != nil {
		t.Fatalf("SetLists: %v", err)
	}

	c := h.clientThroughProxy()
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d", resp.StatusCode)
	}
	ps := resp.Header.Get(HeaderProxyStatus)
	// Inline-list deny goes through SourceDenyList, not SourceRule —
	// the details field MUST NOT carry a "rule X:" prefix.
	if strings.Contains(ps, "details=\"rule ") {
		t.Errorf("inline-list deny should not have rule prefix in details: %q", ps)
	}
	if !strings.Contains(ps, "error=http_request_denied") {
		t.Errorf("error token: %q", ps)
	}
}
