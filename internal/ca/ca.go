// Package ca generates and manages trollbridge's local CA + on-demand
// leaf certs for TLS interception. See DESIGN.md §7.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// KeyType selects the key shape used for the CA root and for newly-
// minted leaf certs.
type KeyType string

const (
	KeyTypeRSA4096   KeyType = "rsa-4096"
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
)

// CA bundles a parsed root cert + private key.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	KeyType KeyType

	certPath string
	keyPath  string

	leafKeyType KeyType
	leafTTL     time.Duration

	mu        sync.Mutex
	leafCache map[string]*tls.Certificate
}

// Init generates a new CA and writes cert+key files at certPath and
// keyPath. Refuses if either file already exists unless force=true,
// in which case the existing files are archived to <path>.<rfc3339>.bak.
func Init(certPath, keyPath string, kt KeyType, force bool) (*CA, error) {
	if kt == "" {
		kt = KeyTypeRSA4096
	}
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			if !force {
				return nil, fmt.Errorf("ca init: %s already exists; pass --force to archive and replace", p)
			}
			ts := time.Now().UTC().Format("20060102T150405Z")
			backup := p + "." + ts + ".bak"
			if err := os.Rename(p, backup); err != nil {
				return nil, fmt.Errorf("archive %s: %w", p, err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}

	key, err := generateKey(kt)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	subject := pkix.Name{
		CommonName: fmt.Sprintf("trollbridge local CA %s %s", hostname, time.Now().UTC().Format("20060102")),
		Organization: []string{"trollbridge"},
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               subject,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, public(key), key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert: cert, Key: key, KeyType: kt,
		certPath: certPath, keyPath: keyPath,
		leafKeyType: kt,
		leafTTL:     365 * 24 * time.Hour,
		leafCache:   map[string]*tls.Certificate{},
	}, nil
}

// Load reads an existing CA from disk.
func Load(certPath, keyPath string, leafKeyType KeyType, leafTTL time.Duration) (*CA, error) {
	cBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ca load cert: %w", err)
	}
	kBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca load key: %w", err)
	}
	if err := checkKeyMode(keyPath); err != nil {
		return nil, err
	}
	cBlock, _ := pem.Decode(cBytes)
	if cBlock == nil {
		return nil, errors.New("ca load: cert PEM decode failed")
	}
	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca load cert parse: %w", err)
	}
	kBlock, _ := pem.Decode(kBytes)
	if kBlock == nil {
		return nil, errors.New("ca load: key PEM decode failed")
	}
	key, err := x509.ParsePKCS8PrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca load key parse: %w", err)
	}
	if leafKeyType == "" {
		leafKeyType = KeyTypeRSA4096
	}
	if leafTTL <= 0 {
		leafTTL = 365 * 24 * time.Hour
	}
	return &CA{
		Cert: cert, Key: key,
		certPath: certPath, keyPath: keyPath,
		leafKeyType: leafKeyType,
		leafTTL:     leafTTL,
		leafCache:   map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the CA's cert as a PEM-encoded byte slice.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// SHA256Fingerprint returns the hex-encoded SHA-256 fingerprint of
// the CA cert (DER form).
func (c *CA) SHA256Fingerprint() string {
	sum := sha256.Sum256(c.Cert.Raw)
	return hex.EncodeToString(sum[:])
}

// LeafFor returns a tls.Certificate suitable for serving TLS as
// `host`. Caches per host+SNI; entries expire when the leaf cert
// expires.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.leafCache[host]; ok {
		if !leafExpired(cached) {
			return cached, nil
		}
		delete(c.leafCache, host)
	}
	leafKey, err := generateKey(c.leafKeyType)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, public(leafKey), c.Key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	out := &tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}
	c.leafCache[host] = out
	return out, nil
}

// IssueClientCert mints a client-auth leaf signed by this CA. The
// returned tls.Certificate carries Leaf populated. Used to give an
// operator (`trollbridge ca client-cert <name>`) credentials for the
// mTLS-locked control plane. CN=name; no SAN; ExtKeyUsage=ClientAuth;
// validity = 1 year.
func (c *CA) IssueClientCert(name string) (*tls.Certificate, error) {
	if name == "" {
		return nil, fmt.Errorf("client-cert name must not be empty")
	}
	leafKey, err := generateKey(c.leafKeyType)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, public(leafKey), c.Key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}, nil
}

// IssueServerCertFor mints a server-auth leaf for a list of SAN
// hosts (DNS names or IPs). Used for the controller's TLS listener.
// Like IssueClientCert this is one-shot — no caching layer; callers
// hold the certificate for the listener's lifetime.
func (c *CA) IssueServerCertFor(cn string, sans []string) (*tls.Certificate, error) {
	leafKey, err := generateKey(c.leafKeyType)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, public(leafKey), c.Key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}, nil
}

// MarshalLeafPEM encodes a leaf cert returned by IssueClientCert /
// IssueServerCertFor as two PEM-encoded byte slices: (cert, key).
// The cert PEM includes the CA cert appended, so callers can serve
// or verify a chain without further work.
func MarshalLeafPEM(leaf *tls.Certificate) (certPEM, keyPEM []byte, err error) {
	var certBuf, keyBuf strings.Builder
	for _, der := range leaf.Certificate {
		if err := pem.Encode(stringWriter{&certBuf}, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return nil, nil, err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(stringWriter{&keyBuf}, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, err
	}
	return []byte(certBuf.String()), []byte(keyBuf.String()), nil
}

type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// ClientCAPool returns a *x509.CertPool containing this CA's root.
// Used by the control plane to verify operator client certs (which
// are issued by IssueClientCert, signed by this same root).
func (c *CA) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

// FlushCache empties the leaf-cert cache.
func (c *CA) FlushCache() {
	c.mu.Lock()
	c.leafCache = map[string]*tls.Certificate{}
	c.mu.Unlock()
}

// CertPath returns the path the CA cert was loaded from.
func (c *CA) CertPath() string { return c.certPath }

// KeyPath returns the path the CA key was loaded from.
func (c *CA) KeyPath() string { return c.keyPath }

func generateKey(kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeRSA4096, "":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unknown key type %q", kt)
	}
}

func public(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func newSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, max)
	return n
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(out, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		out.Close()
		return err
	}
	if cerr := out.Close(); cerr != nil {
		return cerr
	}
	// Lock down the on-disk DACL when this is a key file (mode
	// 0o600). On unix this is a no-op (POSIX bits already enforce
	// owner-only); on Windows applyKeyMode sets a PROTECTED DACL
	// granting only the current user. Closes #107.
	if mode == 0o600 {
		if err := applyKeyMode(path); err != nil {
			return err
		}
	}
	return nil
}

func leafExpired(c *tls.Certificate) bool {
	if c == nil || c.Leaf == nil {
		return true
	}
	return time.Now().After(c.Leaf.NotAfter.Add(-time.Hour))
}
