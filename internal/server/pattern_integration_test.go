package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestPatternAudit_HTTP_ArmRecognized_DecoratedOnAuditEntry covers
// the HTTP plain-proxy entry point. A request to a host that ARM
// recognizes must produce an audit entry with pattern_name and
// pattern_components populated, regardless of which rule decided.
// Closes #203.
func TestPatternAudit_HTTP_ArmRecognized_DecoratedOnAuditEntry(t *testing.T) {
	// Deny rule on management.azure.com so the request never
	// forwards (no need for a real upstream). The audit entry is
	// still written by the deny path.
	rules := `
- id: deny-arm
  match:
    host: management.azure.com
  effect: deny
`
	_, addr, auditPath, cancel, done := bootHostlistProxy(t, "", "", rules, nil)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 3 * time.Second}

	// Construct an ARM-shaped URL. We point at port 80 (HTTP) so
	// no TLS interception is needed; the proxy still recognizes
	// host=management.azure.com per the registry.
	armURL := "http://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1?api-version=2023-01-01"
	req, err := http.NewRequest("GET", armURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		// The proxy will refuse with an error response; that's
		// expected. We tolerate either a refusal status code or
		// a transport-level error since the deny path may close
		// the connection.
		if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "connection") {
			t.Fatalf("unexpected client error: %v", err)
		}
	} else {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Wait briefly for the audit to flush.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	entries := auditEntries(t, auditPath)
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	var arm *struct {
		Name  string
		Comps map[string]string
	}
	for _, e := range entries {
		if e.Host == "management.azure.com" && e.PatternName != "" {
			arm = &struct {
				Name  string
				Comps map[string]string
			}{e.PatternName, e.PatternComponents}
			break
		}
	}
	if arm == nil {
		t.Fatalf("no audit entry with pattern_name set; entries: %+v", entries)
	}
	if arm.Name != "azure_arm" {
		t.Fatalf("pattern_name = %q, want azure_arm", arm.Name)
	}
	if got := arm.Comps["subscription"]; got != "SUB-A" {
		t.Fatalf("components.subscription = %q, want SUB-A", got)
	}
	if got := arm.Comps["resource_type"]; got != "virtualMachines" {
		t.Fatalf("components.resource_type = %q, want virtualMachines", got)
	}
}

// TestPatternAudit_HTTP_NonPatternHost_NoDecoration covers the
// negative case: a host that no pattern recognizes produces an
// audit entry with pattern_name empty and pattern_components nil.
func TestPatternAudit_HTTP_NonPatternHost_NoDecoration(t *testing.T) {
	// Send a request to a generic test origin. Configure an
	// allow rule for it so the request flows through.
	rules := ""
	allow := "127.0.0.1\n"

	// Spin a trivial upstream so the proxy has somewhere to go.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Read(make([]byte, 1024))
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}(c)
		}
	}()

	_, addr, auditPath, cancel, done := bootHostlistProxy(t, allow, "", rules, nil)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 3 * time.Second}
	host, port, _ := net.SplitHostPort(upstream.Addr().String())
	resp, err := c.Get(fmt.Sprintf("http://%s:%s/foo", host, port))
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	entries := auditEntries(t, auditPath)
	for _, e := range entries {
		if e.PatternName != "" {
			t.Fatalf("non-pattern host should not carry pattern_name; got %q on host=%s", e.PatternName, e.Host)
		}
		if e.PatternComponents != nil {
			t.Fatalf("non-pattern host should not carry pattern_components; got %+v", e.PatternComponents)
		}
	}
}

// TestPatternRule_Decision covers the rule-engine integration end
// to end. A pattern rule fires when ARM recognition matches.
func TestPatternRule_Decision(t *testing.T) {
	rules := `
- id: deny-arm-deletes
  match:
    pattern: azure_arm
    method: DELETE
  effect: deny
- id: allow-arm-gets
  match:
    pattern: azure_arm
    method: GET
  effect: allow
`
	_, addr, auditPath, cancel, done := bootHostlistProxy(t, "", "", rules, nil)
	defer func() { cancel(); <-done }()

	pURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 3 * time.Second}

	// DELETE on ARM → deny rule fires
	req, _ := http.NewRequest("DELETE", "http://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1", nil)
	resp, err := c.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	entries := auditEntries(t, auditPath)
	var armDelete *struct {
		Decision string
		Rule     string
	}
	for _, e := range entries {
		if e.Method == "DELETE" && e.PatternName == "azure_arm" {
			armDelete = &struct {
				Decision string
				Rule     string
			}{e.Decision, e.RuleID}
		}
	}
	if armDelete == nil {
		t.Fatalf("expected audit entry for ARM DELETE; entries: %+v", entries)
	}
	if armDelete.Decision != "deny" {
		t.Fatalf("ARM DELETE: decision = %s, want deny", armDelete.Decision)
	}
	if armDelete.Rule != "deny-arm-deletes" {
		t.Fatalf("ARM DELETE: rule_id = %s, want deny-arm-deletes", armDelete.Rule)
	}
}
