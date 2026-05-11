package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

func TestClassifyClientHandshakeError_KnownShapes(t *testing.T) {
	// Each row pairs an error shape crypto/tls actually produces with
	// the category an operator should see in the audit log. The
	// strings are the long-stable forms; if the Go runtime renames
	// one, the matching case in classifyClientHandshakeError must be
	// updated in lockstep (and this test will fire).
	cases := []struct {
		name string
		err  error
		want TLSErrorCategory
	}{
		{
			name: "client rejected our CA (post-cert alert)",
			err:  errors.New("remote error: tls: unknown certificate authority"),
			want: TLSErrClientRejectedCA,
		},
		{
			name: "client rejected our CA (bad certificate alert)",
			err:  errors.New("remote error: tls: bad certificate"),
			want: TLSErrClientRejectedCA,
		},
		{
			name: "x509 verify failure shape",
			err:  errors.New("x509: certificate signed by unknown authority"),
			want: TLSErrClientRejectedCA,
		},
		{
			name: "ALPN mismatch",
			err:  errors.New("tls: no application protocol"),
			want: TLSErrClientALPNMismatch,
		},
		{
			name: "cipher mismatch",
			err:  errors.New("tls: no cipher suite supported by both client and server"),
			want: TLSErrClientCipherMismatch,
		},
		{
			name: "version unsupported",
			err:  errors.New("tls: client offered only unsupported versions: [SSLv3]"),
			want: TLSErrClientVersionUnsupported,
		},
		{
			name: "non-TLS bytes",
			err:  errors.New("tls: first record does not look like a TLS handshake"),
			want: TLSErrMalformedClientHello,
		},
		{
			name: "EOF before handshake",
			err:  io.EOF,
			want: TLSErrClientClosed,
		},
		{
			name: "ECONNRESET",
			err:  syscall.ECONNRESET,
			want: TLSErrClientClosed,
		},
		{
			name: "deadline exceeded → timeout",
			err:  os.ErrDeadlineExceeded,
			want: TLSErrHandshakeTimeout,
		},
		{
			name: "completely unknown",
			err:  errors.New("something totally unrelated"),
			want: TLSErrUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyClientHandshakeError(c.err)
			if got != c.want {
				t.Errorf("ClassifyClientHandshakeError(%q) = %q, want %q", c.err.Error(), got, c.want)
			}
		})
	}
}

func TestClassifyOriginTLSError_KnownShapes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want TLSErrorCategory
	}{
		{
			name: "upstream cert unknown CA",
			err:  errors.New("x509: certificate signed by unknown authority"),
			want: TLSErrUpstreamCertInvalid,
		},
		{
			name: "upstream cert hostname mismatch",
			err:  errors.New("x509: certificate is valid for foo.example.com, not bar.example.com"),
			want: TLSErrUpstreamCertInvalid,
		},
		{
			name: "upstream cert expired",
			err:  errors.New("x509: certificate has expired or is not yet valid"),
			want: TLSErrUpstreamCertInvalid,
		},
		{
			name: "upstream TLS alert",
			err:  errors.New("remote error: tls: handshake failure"),
			want: TLSErrUpstreamCertInvalid,
		},
		{
			name: "upstream connection refused",
			err:  errors.New("dial tcp 192.0.2.1:443: connect: connection refused"),
			want: TLSErrUpstreamConnect,
		},
		{
			name: "upstream DNS failure",
			err:  errors.New("dial tcp: lookup nonexistent.example.com: no such host"),
			want: TLSErrUpstreamConnect,
		},
		{
			name: "upstream i/o timeout",
			err:  errors.New("read tcp 1.2.3.4:443: i/o timeout"),
			want: TLSErrUpstreamConnect,
		},
		{
			name: "completely unknown",
			err:  errors.New("something totally unrelated"),
			want: TLSErrUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyOriginTLSError(c.err)
			if got != c.want {
				t.Errorf("ClassifyOriginTLSError(%q) = %q, want %q", c.err.Error(), got, c.want)
			}
		})
	}
}

func TestSnapshotFromClientHello_CarriesSNIALPNAndVersions(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		ServerName:        "api.example.com",
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	got := snapshotFromClientHello(chi)
	if got.SNI != "api.example.com" {
		t.Errorf("SNI: got %q, want %q", got.SNI, "api.example.com")
	}
	if fmt.Sprintf("%v", got.OfferedALPN) != "[h2 http/1.1]" {
		t.Errorf("ALPN: got %v, want [h2 http/1.1]", got.OfferedALPN)
	}
	want := []string{"TLS 1.3", "TLS 1.2"}
	if fmt.Sprintf("%v", got.OfferedVersions) != fmt.Sprintf("%v", want) {
		t.Errorf("Versions: got %v, want %v", got.OfferedVersions, want)
	}
	if len(got.OfferedCipherSuites) != 2 {
		t.Errorf("CipherSuites count: got %d, want 2", len(got.OfferedCipherSuites))
	}
	for _, name := range got.OfferedCipherSuites {
		if name == "" || name == "0x0000" {
			t.Errorf("unresolved cipher suite name: %q", name)
		}
	}
}

func TestSnapshotFromClientHello_NilSafe(t *testing.T) {
	got := snapshotFromClientHello(nil)
	if got.SNI != "" || got.OfferedALPN != nil || got.OfferedVersions != nil {
		t.Errorf("nil ClientHelloInfo should yield zero snapshot, got %+v", got)
	}
}

func TestMakeCaptureConfig_RecordsHelloBeforeHandshake(t *testing.T) {
	// We don't actually drive a handshake here — just confirm the
	// callback wiring runs and writes into the recorder. Calling
	// GetConfigForClient manually mimics what crypto/tls does on
	// every connection.
	base := &tls.Config{}
	wrapped, rec := makeCaptureConfig(base)
	if wrapped.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient not installed")
	}
	cfg, err := wrapped.GetConfigForClient(&tls.ClientHelloInfo{
		ServerName: "x.example",
	})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if cfg != nil {
		t.Errorf("callback should return nil cfg (use base); got %v", cfg)
	}
	snap := rec.snapshot()
	if snap.SNI != "x.example" {
		t.Errorf("recorded SNI: got %q, want %q", snap.SNI, "x.example")
	}
}
