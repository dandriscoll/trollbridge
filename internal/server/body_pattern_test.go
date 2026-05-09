package server

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBodyPattern_AppliesWhenSampleMatches(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got: %s", string(body))
	}))
	defer origin.Close()
	originHostOnly, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	rules := fmt.Sprintf(`
- id: deny-secret-bodies
  priority: 500
  match:
    host: %s
    method: POST
    body_pattern: "(?i)secret"
  effect: deny

- id: allow-other-posts
  priority: 100
  match:
    host: %s
    method: POST
  effect: allow
`, originHostOnly, originHostOnly)
	h := bootApprovalProxy(t, rules, 5, "deny")
	defer h.close()

	pURL, _ := url.Parse("http://" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}

	// Body without "secret" → allow path.
	resp, err := c.Post(origin.URL, "text/plain", bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "hello world") {
		t.Errorf("clean body: got status=%d body=%q, want 200 with echo", resp.StatusCode, string(body))
	}

	// Body containing "secret" → deny path.
	resp, err = c.Post(origin.URL, "text/plain", bytes.NewReader([]byte("here is a SECRET token")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != StatusTrollbridgeDeclined {
		t.Errorf("secret body: got status=%d, want %d", resp.StatusCode, StatusTrollbridgeDeclined)
	}
}
