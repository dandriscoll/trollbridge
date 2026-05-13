package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/ca"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/sessions"
)

// bootControl starts a control plane backed by a fresh test CA and
// returns: the server, its bound address, the CA itself (so tests
// can mint client certs), and a cancel func.
func bootControl(t *testing.T) (*Server, string, *ca.CA, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	caObj, err := ca.Init(caCert, caKey, ca.KeyTypeECDSAP256, false)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ca.Load(caCert, caKey, ca.KeyTypeECDSAP256, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = caObj

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	q := approvals.New(8, time.Second, "deny")
	tk := sessions.New()
	eng, _ := policy.NewEngine("default-deny", nil, policy.KnownModifiers())
	s := New(addr, q, tk, eng)
	s.SetTLS(loaded)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.ListenAndServe(ctx); err != nil {
		t.Fatalf("control listen: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	return s, addr, loaded, cancel
}

func clientWithCert(t *testing.T, caObj *ca.CA, name string) *http.Client {
	t.Helper()
	leaf, err := caObj.IssueClientCert(name)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caObj.Cert)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*leaf},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
}

func clientNoCert(t *testing.T, caObj *ca.CA) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(caObj.Cert)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
}

func TestControl_MTLS_AcceptsClientWithCert(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientWithCert(t, caObj, "operator-1")
	resp, err := c.Get("https://" + addr + "/v1/holds")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status: got %d, want 200; body=%s", resp.StatusCode, string(body))
	}
}

func TestControl_MTLS_RejectsClientWithoutCert(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientNoCert(t, caObj)
	resp, err := c.Get("https://" + addr + "/v1/holds")
	if err == nil {
		// Some TLS stacks accept the handshake (with verify-if-given)
		// then return 401 from middleware. Either is acceptable.
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 without client cert; got %d", resp.StatusCode)
		}
		return
	}
	// A handshake-time rejection (older client behavior) is also OK.
}

func TestControl_HealthzAlwaysReachable(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientNoCert(t, caObj)
	resp, err := c.Get("https://" + addr + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// stubLists implements ListsProvider for /v1/lists tests (closes #99
// part 1).
type stubLists struct{ allow, deny []string }

func (s stubLists) AllowPatterns() []string { return s.allow }
func (s stubLists) DenyPatterns() []string  { return s.deny }

// TestControl_ListsEndpoint_ReturnsConfiguredPatterns asserts the
// new /v1/lists endpoint serves the wired ListsProvider's data.
func TestControl_ListsEndpoint_ReturnsConfiguredPatterns(t *testing.T) {
	srv, addr, caObj, cancel := bootControl(t)
	defer cancel()
	srv.SetLists(stubLists{
		allow: []string{"github.com", "*.example.com"},
		deny:  []string{"169.254.169.254"},
	})

	c := clientWithCert(t, caObj, "operator-1")
	resp, err := c.Get("https://" + addr + "/v1/lists")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var got struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := jsonUnmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v: %s", err, body)
	}
	if !slicesEqual(got.Allow, []string{"github.com", "*.example.com"}) {
		t.Errorf("allow: got %v, want [github.com *.example.com]", got.Allow)
	}
	if !slicesEqual(got.Deny, []string{"169.254.169.254"}) {
		t.Errorf("deny: got %v, want [169.254.169.254]", got.Deny)
	}
}

// TestControl_ListsEndpoint_NoProviderReturnsEmpty asserts the
// endpoint is reachable even when SetLists was not called — useful
// for older daemon configurations or tests that don't wire the
// provider.
func TestControl_ListsEndpoint_NoProviderReturnsEmpty(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientWithCert(t, caObj, "operator-1")
	resp, err := c.Get("https://" + addr + "/v1/lists")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var got struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := jsonUnmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Allow) != 0 || len(got.Deny) != 0 {
		t.Errorf("expected empty allow/deny; got allow=%v deny=%v", got.Allow, got.Deny)
	}
}

// TestControl_LLMDigestsEndpoint_NoProviderReturnsEmpty: the
// endpoint must respond even when the daemon has no advisor.
func TestControl_LLMDigestsEndpoint_NoProviderReturnsEmpty(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientWithCert(t, caObj, "operator-1")
	resp, err := c.Get("https://" + addr + "/v1/llm-digests")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got []any
	if err := jsonUnmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v: %s", err, body)
	}
	if len(got) != 0 {
		t.Errorf("expected empty array; got %v", got)
	}
}

// jsonUnmarshal aliases encoding/json.Unmarshal so the test calls
// read uniformly even if a future refactor changes the import path.
var jsonUnmarshal = json.Unmarshal

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
