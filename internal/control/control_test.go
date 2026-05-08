package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/dandriscoll/drawbridge/internal/approvals"
	"github.com/dandriscoll/drawbridge/internal/ca"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/sessions"
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
