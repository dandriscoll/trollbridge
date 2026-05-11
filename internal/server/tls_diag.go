package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
)

// TLSErrorCategory is a small taxonomy over the raw crypto/tls error
// strings so an operator can tell, at a glance, *what kind* of TLS
// failure occurred — without having to read Go's TLS error strings.
//
// The categories cover both sides of an intercepted CONNECT:
//   - the client → proxy handshake (where the proxy serves a leaf
//     signed by the trollbridge CA), and
//   - the proxy → upstream handshake (where the proxy verifies the
//     origin against the system / configured roots).
//
// Categories are STABLE strings — they appear in audit.jsonl and in
// operational-log records, so changing one is a breaking change for
// log consumers. Only add new categories; do not rename existing ones.
type TLSErrorCategory string

const (
	// TLSErrUnknown — fallback when no specific category fits. The
	// raw error string is still preserved in the audit entry's
	// `error` field.
	TLSErrUnknown TLSErrorCategory = "unknown"

	// TLSErrClientRejectedCA — the client did not trust the
	// trollbridge CA. The most common interception failure: the
	// operator installed the proxy but the client (browser, Go,
	// curl, Python `requests`) has not been pointed at the
	// trollbridge CA bundle.
	TLSErrClientRejectedCA TLSErrorCategory = "client_rejected_ca"

	// TLSErrClientALPNMismatch — the client and proxy could not
	// agree on an ALPN protocol. trollbridge advertises http/1.1
	// only (see DESIGN.md §6.5); a client that requires h2 with no
	// fallback lands here.
	TLSErrClientALPNMismatch TLSErrorCategory = "client_alpn_mismatch"

	// TLSErrClientCipherMismatch — the client offered no cipher
	// suite acceptable to the proxy (or vice versa).
	TLSErrClientCipherMismatch TLSErrorCategory = "client_cipher_mismatch"

	// TLSErrClientVersionUnsupported — the client offered no TLS
	// version supported by the proxy (proxy minimum is TLS 1.2).
	TLSErrClientVersionUnsupported TLSErrorCategory = "client_version_unsupported"

	// TLSErrHandshakeTimeout — the handshake exceeded the
	// configured deadline. Usually means the client sent a partial
	// ClientHello and stalled.
	TLSErrHandshakeTimeout TLSErrorCategory = "handshake_timeout"

	// TLSErrMalformedClientHello — the client sent bytes that
	// don't parse as a TLS ClientHello. Frequently indicates a
	// non-TLS client speaking plaintext into the tunnel (e.g., a
	// misconfigured agent that thinks it's HTTP).
	TLSErrMalformedClientHello TLSErrorCategory = "malformed_clienthello"

	// TLSErrClientClosed — the client closed the connection before
	// the handshake completed. Often paired with TLSErrClientRejectedCA
	// when the client decided not to proceed after seeing our cert.
	TLSErrClientClosed TLSErrorCategory = "client_closed"

	// TLSErrUpstreamCertInvalid — the proxy could not verify the
	// upstream origin's certificate against its trust roots. This
	// fires on the *origin* TLS dial, not the client-facing
	// handshake.
	TLSErrUpstreamCertInvalid TLSErrorCategory = "upstream_cert_invalid"

	// TLSErrUpstreamConnect — the proxy could not reach the
	// upstream origin (TCP-layer failure surfaced through
	// tls.DialWithDialer).
	TLSErrUpstreamConnect TLSErrorCategory = "upstream_connect"
)

// ClientHelloSnapshot is the structured record of what the TLS
// ClientHello carried. Populated by captureClientHello at handshake
// time; surfaced verbatim in the audit log and the operational log
// so an operator chasing "why didn't the handshake work" can see
// exactly what the client offered.
//
// Fields are intentionally human-readable strings (not raw uint16
// IDs) — the audit log is read by humans first and machines second.
type ClientHelloSnapshot struct {
	SNI                  string   `json:"sni,omitempty"`
	OfferedALPN          []string `json:"alpn,omitempty"`
	OfferedVersions      []string `json:"versions,omitempty"`
	OfferedCipherSuites  []string `json:"cipher_suites,omitempty"`
}

// helloRecorder is a single-shot capture for a ClientHelloInfo, made
// safe for concurrent read by the TLS goroutine and the audit-write
// path. The TLS handshake runs in the same goroutine as the audit
// write that follows it, so the mutex is for defense in depth (some
// crypto/tls versions invoke callbacks from a different goroutine).
type helloRecorder struct {
	mu   sync.Mutex
	snap ClientHelloSnapshot
	got  bool
}

// makeCaptureConfig wraps a base *tls.Config so that the proxy's
// existing certificate selection still works but the ClientHello is
// recorded before the handshake proceeds. Returns the wrapped config
// and a *helloRecorder the caller reads after handshake completion
// (success OR failure).
//
// Implementation note: GetConfigForClient is invoked very early in
// the handshake, *before* certificate selection — so even a handshake
// that fails at the cert-validation step still produces a snapshot.
// The callback may NOT modify `base`; it returns a shallow copy.
func makeCaptureConfig(base *tls.Config) (*tls.Config, *helloRecorder) {
	rec := &helloRecorder{}
	wrapped := base.Clone()
	wrapped.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		rec.mu.Lock()
		rec.snap = snapshotFromClientHello(chi)
		rec.got = true
		rec.mu.Unlock()
		return nil, nil
	}
	return wrapped, rec
}

// snapshot returns a copy of the recorded snapshot. Empty if the
// callback never fired (handshake failed before ClientHello parse).
func (r *helloRecorder) snapshot() ClientHelloSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.got {
		return ClientHelloSnapshot{}
	}
	// Defensive copy of slices.
	out := r.snap
	if len(r.snap.OfferedALPN) > 0 {
		out.OfferedALPN = append([]string(nil), r.snap.OfferedALPN...)
	}
	if len(r.snap.OfferedVersions) > 0 {
		out.OfferedVersions = append([]string(nil), r.snap.OfferedVersions...)
	}
	if len(r.snap.OfferedCipherSuites) > 0 {
		out.OfferedCipherSuites = append([]string(nil), r.snap.OfferedCipherSuites...)
	}
	return out
}

func snapshotFromClientHello(chi *tls.ClientHelloInfo) ClientHelloSnapshot {
	if chi == nil {
		return ClientHelloSnapshot{}
	}
	out := ClientHelloSnapshot{
		SNI:         chi.ServerName,
		OfferedALPN: append([]string(nil), chi.SupportedProtos...),
	}
	for _, v := range chi.SupportedVersions {
		out.OfferedVersions = append(out.OfferedVersions, tlsVersionName(v))
	}
	for _, cs := range chi.CipherSuites {
		out.OfferedCipherSuites = append(out.OfferedCipherSuites, tls.CipherSuiteName(cs))
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// classifyClientHandshakeError maps an error returned by
// tls.Conn.Handshake (server side) to a TLSErrorCategory.
//
// The mapping is intentionally string-driven: crypto/tls reports
// most distinct conditions only via the error text, not via typed
// sentinels. The strings tested here are stable enough (they have
// not changed across recent Go releases) for this taxonomy to be
// useful; if a future Go release renames one, classify falls back to
// TLSErrUnknown and the raw text remains in audit.Error.
func ClassifyClientHandshakeError(err error) TLSErrorCategory {
	if err == nil {
		return ""
	}
	if isTimeoutErr(err) {
		return TLSErrHandshakeTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// Client closed mid-handshake. A common shape:
		//   "remote error: tls: bad certificate" → client rejected
		//   our cert THEN closed. We classify those upstream of this
		//   check via the substring match below; bare EOF falls here.
		return TLSErrClientClosed
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return TLSErrClientClosed
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "remote error: tls: unknown certificate authority"),
		strings.Contains(s, "remote error: tls: bad certificate"),
		strings.Contains(s, "remote error: tls: certificate required"),
		strings.Contains(s, "remote error: tls: certificate unknown"),
		strings.Contains(s, "remote error: tls: unknown ca"),
		strings.Contains(s, "x509: certificate signed by unknown authority"):
		return TLSErrClientRejectedCA
	case strings.Contains(s, "no application protocol"),
		strings.Contains(s, "remote error: tls: no application protocol"),
		strings.Contains(s, "ALPN"):
		return TLSErrClientALPNMismatch
	case strings.Contains(s, "no cipher suite supported"),
		strings.Contains(s, "remote error: tls: handshake failure"),
		strings.Contains(s, "no mutual cipher"):
		return TLSErrClientCipherMismatch
	case strings.Contains(s, "protocol version not supported"),
		strings.Contains(s, "tls: client offered only unsupported versions"),
		strings.Contains(s, "tls: server selected unsupported protocol version"):
		return TLSErrClientVersionUnsupported
	case strings.Contains(s, "first record does not look like a TLS handshake"),
		strings.Contains(s, "tls: unsupported SSLv2 handshake received"),
		strings.Contains(s, "tls: record overflow"),
		strings.Contains(s, "tls: oversized record"):
		return TLSErrMalformedClientHello
	}
	return TLSErrUnknown
}

// classifyOriginTLSError maps an error from the proxy→origin
// tls.DialWithDialer to a TLSErrorCategory. The distinction from
// classifyClientHandshakeError is that here the proxy is the *client*
// and the failure shape is dominated by certificate-verification
// errors against the system / origin roots.
func ClassifyOriginTLSError(err error) TLSErrorCategory {
	if err == nil {
		return ""
	}
	if isTimeoutErr(err) {
		return TLSErrHandshakeTimeout
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "x509: certificate signed by unknown authority"),
		strings.Contains(s, "x509: certificate is valid for"),
		strings.Contains(s, "x509: certificate has expired"),
		strings.Contains(s, "x509:"):
		return TLSErrUpstreamCertInvalid
	case strings.Contains(s, "connection refused"),
		strings.Contains(s, "no route to host"),
		strings.Contains(s, "network is unreachable"),
		strings.Contains(s, "no such host"),
		strings.Contains(s, "i/o timeout"):
		return TLSErrUpstreamConnect
	case strings.Contains(s, "remote error: tls:"):
		// Upstream sent an alert. Most often "handshake failure" or
		// "protocol version" — those are upstream-side rejections.
		return TLSErrUpstreamCertInvalid
	}
	return TLSErrUnknown
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
