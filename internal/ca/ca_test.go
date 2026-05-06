package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tmpCA(t *testing.T, kt KeyType) (*CA, string, string) {
	t.Helper()
	dir := t.TempDir()
	cp := filepath.Join(dir, "ca.crt")
	kp := filepath.Join(dir, "ca.key")
	c, err := Init(cp, kp, kt, false)
	if err != nil {
		t.Fatal(err)
	}
	return c, cp, kp
}

func TestInit_WritesCertAndKey(t *testing.T) {
	c, cp, kp := tmpCA(t, KeyTypeECDSAP256) // ECDSA for speed
	if _, err := os.Stat(cp); err != nil {
		t.Errorf("missing cert file: %v", err)
	}
	info, err := os.Stat(kp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 0600", info.Mode().Perm())
	}
	if c.SHA256Fingerprint() == "" {
		t.Error("empty fingerprint")
	}
	if !c.Cert.IsCA {
		t.Error("cert is not marked CA")
	}
}

func TestInit_RefusesIfFilesExistWithoutForce(t *testing.T) {
	c, cp, kp := tmpCA(t, KeyTypeECDSAP256)
	_ = c
	if _, err := Init(cp, kp, KeyTypeECDSAP256, false); err == nil {
		t.Fatal("expected refusal without --force")
	}
}

func TestInit_ForceArchives(t *testing.T) {
	_, cp, kp := tmpCA(t, KeyTypeECDSAP256)
	if _, err := Init(cp, kp, KeyTypeECDSAP256, true); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(cp)
	matches, _ := filepath.Glob(filepath.Join(dir, "*.bak"))
	if len(matches) < 2 { // both cert and key archived
		t.Errorf("expected at least 2 .bak files, got %d", len(matches))
	}
}

func TestLoad_RefusesPermissiveKey(t *testing.T) {
	_, cp, kp := tmpCA(t, KeyTypeECDSAP256)
	if err := os.Chmod(kp, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cp, kp, KeyTypeECDSAP256, 0); err == nil {
		t.Fatal("expected Load to refuse 0644 key")
	}
}

func TestLeafFor_GeneratesAndCachesPerHost(t *testing.T) {
	c, _, _ := tmpCA(t, KeyTypeECDSAP256)
	a, err := c.LeafFor("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.LeafFor("b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("leaf certs for different hosts should differ")
	}
	a2, _ := c.LeafFor("a.example.com")
	if a != a2 {
		t.Error("cache miss on repeated host lookup")
	}
}

func TestLeafFor_ServerSideTLSHandshake(t *testing.T) {
	// Spin up a TLS server using a leaf cert; have a TLS client
	// trust the CA and verify the handshake succeeds.
	c, _, _ := tmpCA(t, KeyTypeECDSAP256)
	leaf, err := c.LeafFor("test-host.local")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello"))
		}),
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)

	dialer := &net.Dialer{}
	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	_ = host
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{
		ServerName: "test-host.local",
		RootCAs:    pool,
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	conn.Close()
}

func TestFlushCache_DropsLeaves(t *testing.T) {
	c, _, _ := tmpCA(t, KeyTypeECDSAP256)
	a, _ := c.LeafFor("x.example.com")
	c.FlushCache()
	a2, _ := c.LeafFor("x.example.com")
	if a == a2 {
		t.Error("expected different leaf after flush; got same")
	}
}

// httptest sanity: avoid an import-only error.
var _ = httptest.NewServer

// strings sanity (used elsewhere in this file's tests sometimes).
var _ = strings.HasPrefix
