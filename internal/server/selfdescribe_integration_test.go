package server

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/selfdescribe"
)

// TestServeHTTP_SelfDescribeShortCircuit drives a forward-proxy
// request to the magic host through a real running proxy and asserts
// the self-describe index is returned (not the policy engine's
// 470/471). Closes #38: the dispatcher must short-circuit.
func TestServeHTTP_SelfDescribeShortCircuit(t *testing.T) {
	proxyAddr, _, _, cleanup := bootHTTPProxyWithOpLog(t, 0)
	defer cleanup()

	body, status := proxyRoundTrip(t, proxyAddr,
		"GET http://"+selfdescribe.MagicHost+"/setup HTTP/1.1\r\n"+
			"Host: "+selfdescribe.MagicHost+"\r\n"+
			"Connection: close\r\n\r\n")
	if status != 200 {
		t.Fatalf("status = %d, want 200 (self-describe should bypass the engine)\nbody: %q", status, body)
	}
	for _, want := range []string{"/setup/proxied-agent.md", "/setup/instructions.md", "/setup/env"} {
		if !strings.Contains(body, want) {
			t.Errorf("self-describe index missing %q in body:\n%s", want, body)
		}
	}
}

// TestServeHTTP_NonMagicHostStillReachesEngine verifies the negative
// case: a forwarded GET to an unrelated host still passes through
// the policy engine. Under the test fixture's default-deny posture
// with no matching rule, the proxy returns 470.
func TestServeHTTP_NonMagicHostStillReachesEngine(t *testing.T) {
	proxyAddr, _, _, cleanup := bootHTTPProxyWithOpLog(t, 0)
	defer cleanup()

	_, status := proxyRoundTrip(t, proxyAddr,
		"GET http://blocked.example.com/foo HTTP/1.1\r\n"+
			"Host: blocked.example.com\r\n"+
			"Connection: close\r\n\r\n")
	if status != 470 {
		t.Errorf("status = %d, want 470 (non-magic host should hit the engine)", status)
	}
}

// TestServeHTTP_SelfDescribeServesProxiedAgent fetches the embedded
// PROXIED-AGENT.md through a forwarded request.
func TestServeHTTP_SelfDescribeServesProxiedAgent(t *testing.T) {
	proxyAddr, _, _, cleanup := bootHTTPProxyWithOpLog(t, 0)
	defer cleanup()

	body, status := proxyRoundTrip(t, proxyAddr,
		"GET http://"+selfdescribe.MagicHost+"/setup/proxied-agent.md HTTP/1.1\r\n"+
			"Host: "+selfdescribe.MagicHost+"\r\n"+
			"Connection: close\r\n\r\n")
	if status != 200 {
		t.Fatalf("status = %d, want 200; body=%q", status, body)
	}
	if !strings.Contains(body, "Trollbridge-Request-Id") {
		t.Errorf("proxied-agent body missing the contract content; body:\n%s", body)
	}
}

// proxyRoundTrip dials the proxy, sends raw, reads the response,
// and returns (body, statusCode).
func proxyRoundTrip(t *testing.T, addr, request string) (string, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return parseHTTPResponse(string(raw))
}

func parseHTTPResponse(s string) (body string, status int) {
	idx := strings.Index(s, " ")
	if idx < 0 {
		return s, 0
	}
	rest := s[idx+1:]
	idx2 := strings.Index(rest, " ")
	if idx2 < 0 {
		return s, 0
	}
	for _, ch := range rest[:idx2] {
		if ch < '0' || ch > '9' {
			return s, 0
		}
		status = status*10 + int(ch-'0')
	}
	bodyIdx := strings.Index(s, "\r\n\r\n")
	if bodyIdx >= 0 {
		body = s[bodyIdx+4:]
	}
	return body, status
}
