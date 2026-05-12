package ca

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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

// TestCAClientCert_HonorsConfigLeafKeyType asserts that the
// leafKeyType passed to Load is honored when issuing the three
// kinds of leaf certificate the CA produces: server-auth interception
// leaves (LeafFor), client-auth control-plane creds (IssueClientCert),
// and the controller's TLS-listener leaf (IssueServerCertFor).
//
// Filed at job 058 NF-1 and deferred at the time of the #28 fix that
// added LeafKeyType to config without an assertion that the field
// actually drives the runtime path. Closing the deferral guards
// against a future config-vs-runtime drift where the YAML key is
// parsed but ignored.
func TestCAClientCert_HonorsConfigLeafKeyType(t *testing.T) {
	cases := []struct {
		name        string
		rootKT      KeyType
		leafKT      KeyType
		wantLeafKey any // type-only check: &ecdsa.PublicKey{} or &rsa.PublicKey{}
	}{
		{"ECDSA leaves under ECDSA root", KeyTypeECDSAP256, KeyTypeECDSAP256, &ecdsa.PublicKey{}},
		// RSA leaves under an ECDSA root exercises the case where
		// `interception.leaf_key_type` overrides the root's key type
		// — the config drives the leaf type independently.
		{"RSA leaves under ECDSA root (config override)", KeyTypeECDSAP256, KeyTypeRSA4096, &rsa.PublicKey{}},
		{"ECDSA leaves under RSA root (config override)", KeyTypeRSA4096, KeyTypeECDSAP256, &ecdsa.PublicKey{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cp := filepath.Join(dir, "ca.crt")
			kp := filepath.Join(dir, "ca.key")
			// Init writes the root cert+key with rootKT.
			if _, err := Init(cp, kp, tc.rootKT, false); err != nil {
				t.Fatalf("Init(%s): %v", tc.rootKT, err)
			}
			// Load with the leaf override — this is the path the
			// proxy takes at startup using the config-driven
			// `interception.leaf_key_type`.
			c, err := Load(cp, kp, tc.leafKT, 0)
			if err != nil {
				t.Fatalf("Load(%s leafKT=%s): %v", tc.rootKT, tc.leafKT, err)
			}

			// 1) Interception leaf (LeafFor).
			leaf, err := c.LeafFor("test.example.com")
			if err != nil {
				t.Fatalf("LeafFor: %v", err)
			}
			assertPubKeyType(t, "LeafFor", leaf.Leaf.PublicKey, tc.wantLeafKey)

			// 2) Control-plane client cert.
			client, err := c.IssueClientCert("operator-1")
			if err != nil {
				t.Fatalf("IssueClientCert: %v", err)
			}
			assertPubKeyType(t, "IssueClientCert", client.Leaf.PublicKey, tc.wantLeafKey)

			// 3) Controller TLS listener cert.
			server, err := c.IssueServerCertFor("controller", []string{"127.0.0.1"})
			if err != nil {
				t.Fatalf("IssueServerCertFor: %v", err)
			}
			assertPubKeyType(t, "IssueServerCertFor", server.Leaf.PublicKey, tc.wantLeafKey)
		})
	}
}

func assertPubKeyType(t *testing.T, where string, got any, want any) {
	t.Helper()
	switch want.(type) {
	case *ecdsa.PublicKey:
		if _, ok := got.(*ecdsa.PublicKey); !ok {
			t.Errorf("%s: leaf public key type = %T, want *ecdsa.PublicKey", where, got)
		}
	case *rsa.PublicKey:
		if _, ok := got.(*rsa.PublicKey); !ok {
			t.Errorf("%s: leaf public key type = %T, want *rsa.PublicKey", where, got)
		}
	default:
		t.Fatalf("test bug: unrecognized want %T", want)
	}
}

// httptest sanity: avoid an import-only error.
var _ = httptest.NewServer

// strings sanity (used elsewhere in this file's tests sometimes).
var _ = strings.HasPrefix
