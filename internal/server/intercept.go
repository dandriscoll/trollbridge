package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/google/uuid"
)

// shouldIntercept returns true if interception is enabled and the
// host is not on the passthrough list.
func (s *Server) shouldIntercept(host string) bool {
	if s.ca == nil || !s.cfg.Interception.Enabled {
		return false
	}
	hl := strings.ToLower(host)
	for _, pat := range s.cfg.Interception.PassthroughHosts {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == hl {
			return false
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:]
			if strings.HasSuffix(hl, suffix) && len(hl) > len(suffix) {
				return false
			}
		}
	}
	return true
}

// handshakeDeadline bounds how long the proxy will wait for the
// inner TLS handshake on an intercepted CONNECT. A client that opens
// the tunnel then sends nothing (or a partial ClientHello) would
// otherwise pin a goroutine indefinitely. 15s is generous — a normal
// TLS handshake is well under a second — and short enough that
// stalled clients surface as `tls_error_category=handshake_timeout`
// in the audit log rather than as silent leaks.
const interceptHandshakeDeadline = 15 * time.Second

// interceptCONNECT terminates the CONNECT tunnel as TLS, performs
// per-HTTP-request policy decisions on the inner stream, and
// proxies HTTP/1.1 to the origin under a verified TLS dial.
//
// connectReqID is the request_id of the outer CONNECT op already
// in the ring under `CONNECT host:port`. The first successfully-
// dispatched inner request rebinds that entry to its own
// method+URL (closes #75); subsequent inner requests on the same
// tunnel get fresh entries via the usual Begin path.
func (s *Server) interceptCONNECT(clientConn net.Conn, host string, port int, sessionID, identityID, connectReqID string) error {
	leaf, err := s.ca.LeafFor(host)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}
	baseCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		// ALPN h1 only in Phase 3 — DESIGN.md §6.5.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	// Wrap the config so we record the ClientHello (SNI / ALPN /
	// versions / cipher suites) before cert selection. The snapshot
	// is what makes TLS handshake failures actually diagnosable —
	// without it the audit log would only carry crypto/tls's terse
	// error string.
	tlsCfg, helloRec := makeCaptureConfig(baseCfg)
	handshakeStart := time.Now()
	_ = clientConn.SetDeadline(time.Now().Add(interceptHandshakeDeadline))
	tlsConn := tls.Server(clientConn, tlsCfg)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		// The TLS handshake never completed — there is no inner
		// HTTP request to attribute this to, but the operator still
		// needs an audit-shaped record (and a correlated operational
		// log line) so that "TLS to trollbridge stopped working" is
		// debuggable. Mint a synthetic request_id, classify the
		// failure, and carry the recorded ClientHello so the
		// operator can see what the client actually offered.
		requestID := uuid.NewString()
		hello := helloRec.snapshot()
		category := ClassifyClientHandshakeErrorAfter(err, helloRec.got)
		opURL := fmt.Sprintf("https://%s:%d", host, port)
		s.ops.Begin(requestID, "TLS", opURL)
		s.opLog.Warn("intercept TLS handshake failure",
			"event", oplog.EventInterceptHandshakeFail,
			"request_id", requestID,
			"identity", identityID,
			"host", host, "port", port,
			"tls_error_category", string(category),
			"tls_sni", hello.SNI,
			"tls_alpn", strings.Join(hello.OfferedALPN, ","),
			"tls_versions", strings.Join(hello.OfferedVersions, ","),
			"tls_cipher_suites", strings.Join(hello.OfferedCipherSuites, ","),
			"error", err.Error())
		s.writeAuditTLSHandshakeFail(&types.RequestEvent{
			ID:         requestID,
			SessionID:  sessionID,
			IdentityID: identityID,
			Timestamp:  time.Now().UTC(),
			Method:     "?",
			Scheme:     "https-intercepted",
			Host:       host,
			Port:       port,
			ClientAddr: clientConn.RemoteAddr().String(),
		}, types.Decision{
			Effect: types.EffectDeny,
			Source: types.SourceTLSHandshakeFail,
			Reason: "TLS handshake failed (" + string(category) + "): " + err.Error(),
		}, category, hello, http.StatusBadGateway, time.Since(handshakeStart), err.Error())
		return fmt.Errorf("tls server handshake: %w", err)
	}
	// Handshake succeeded — clear the deadline so the inner HTTP
	// request loop is not bounded by the handshake budget.
	_ = clientConn.SetDeadline(time.Time{})

	br := bufio.NewReader(tlsConn)
	connectRebound := false
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// Malformed request from inside the tunnel. Audit-log
			// the parse failure so an operator reviewing logs
			// can see suspicious behavior, even though we have
			// no path / method to attribute. Carry-forward 033.I.4.
			s.writeAudit(&types.RequestEvent{
				ID:         uuid.NewString(),
				SessionID:  sessionID,
				IdentityID: identityID,
				Timestamp:  time.Now().UTC(),
				Method:     "?",
				Scheme:     "https-intercepted",
				Host:       host,
				Port:       port,
				ClientAddr: clientConn.RemoteAddr().String(),
			}, types.Decision{
				Effect: types.EffectDeny,
				Source: types.SourceMalformedTunnel,
				Reason: "malformed HTTP/1.1 request inside intercepted TLS tunnel",
			}, "", 0, http.StatusBadRequest, 0, 0, err.Error())
			return nil
		}
		// Reconstruct a full URL because http.ReadRequest gives us
		// just the path.
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		if !strings.Contains(req.URL.Host, ":") && port != 443 {
			req.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
		}

		if err := s.dispatchInterceptedRequest(tlsConn, req, host, port, sessionID, identityID, connectReqID, &connectRebound); err != nil {
			s.opLog.Error("intercept dispatch error",
				"event", oplog.EventInterceptError,
				"host", host, "port", port,
				"error", err.Error())
			return err
		}
		// Connection: close → exit the loop.
		if strings.EqualFold(req.Header.Get("Connection"), "close") {
			return nil
		}
	}
}

func (s *Server) dispatchInterceptedRequest(tlsConn *tls.Conn, r *http.Request, host string, port int, sessionID, identityID, connectReqID string, connectRebound *bool) error {
	start := time.Now()
	requestID := uuid.NewString()

	// Read body for inspection (bounded). For over-cap bodies the
	// sample is dropped (engine fails closed on body-required
	// rules per the carry-forward fix) but the FULL body is still
	// forwarded to the origin via MultiReader so that legitimate
	// large uploads are not truncated. The cost of the bounded
	// read is the prefix bytes; the rest streams from the
	// original reader.
	var bodyBuf []byte
	if r.Body != nil && s.MaxBodySampleBytes > 0 {
		prefix, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxBodySampleBytes)+1))
		if err != nil {
			return err
		}
		if int64(len(prefix)) > int64(s.MaxBodySampleBytes) {
			// Over cap. No sample for the engine. Forward the
			// full body by stitching prefix + rest.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
		} else {
			// Fits; sample IS the body.
			bodyBuf = prefix
			r.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		}
	}

	req := &types.RequestEvent{
		ID:         requestID,
		SessionID:  sessionID,
		IdentityID: identityID,
		Timestamp:  start,
		Method:     r.Method,
		Scheme:     "https-intercepted",
		Host:       host,
		Port:       port,
		Path:       r.URL.Path,
		Headers:    r.Header.Clone(),
		ClientAddr: tlsConn.RemoteAddr().String(),
	}
	if int64(len(bodyBuf)) <= int64(s.MaxBodySampleBytes) && len(bodyBuf) > 0 {
		req.BodySample = bodyBuf
		req.BodyAvailable = true
		req.BodySize = int64(len(bodyBuf))
	}

	opURL := opURLForRequest(req)
	if !*connectRebound && s.ops.Rebind(connectReqID, req.ID, req.Method, opURL) {
		*connectRebound = true
	} else {
		s.ops.Begin(req.ID, req.Method, opURL)
	}

	rlog := s.opLog.With(
		"request_id", req.ID,
		"identity", identityID,
		"method", r.Method,
		"scheme", "https-intercepted",
		"host", host,
		"port", port,
	)
	rlog.Debug("received", "phase", oplog.PhaseReceived, "path", req.Path)

	s.recognizePattern(req, rlog)

	decision, fastHit := s.fastPathDecide(req.Method, "https", host, port, req.Path)
	if fastHit {
		rlog.Debug("fastpath_eval", "phase", oplog.PhaseFastpathEval,
			"hit", true, "decision", string(decision.Effect),
			"source", string(decision.Source), "rule_id", decision.RuleID)
	} else {
		rlog.Debug("fastpath_eval", "phase", oplog.PhaseFastpathEval, "hit", false)
		decision = s.engine.Decide(req)
		rlog.Debug("engine_eval", "phase", oplog.PhaseEngineEval,
			"decision", string(decision.Effect),
			"source", string(decision.Source), "rule_id", decision.RuleID)
	}
	if decision.Effect == types.EffectAskUser || decision.Effect == types.EffectAskLLM {
		rlog.Debug("held", "phase", oplog.PhaseHeld, "effect", string(decision.Effect))
		decision = s.holdAndWait(req, decision)
		rlog.Debug("resolved", "phase", oplog.PhaseResolved, "effect", string(decision.Effect))
	}
	s.transitionOpFromEvaluating(req.ID, decision.Effect)
	s.engine.History().Record(req, decision, time.Now().UTC())

	if !(decision.Effect == types.EffectAllow || decision.Effect == types.EffectAskUserResolvedAllow) {
		// Refuse: emit a trollbridge-categorical status (470/471)
		// over the intercepted TLS connection.
		hdrs, body, contentType := denyResponse(decision, req.ID, r.Header.Get("Accept"))
		respHeader := http.Header{
			"Content-Type":   {contentType},
			"Content-Length": {strconv.Itoa(len(body))},
			"Connection":     {"close"},
		}
		for k, v := range hdrs {
			respHeader.Set(k, v)
		}
		status := statusFromEffect(decision.Effect)
		resp := &http.Response{
			StatusCode: status,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1, ProtoMinor: 1,
			Header:        respHeader,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		_ = resp.Write(tlsConn)
		rlog.Debug("response", "phase", oplog.PhaseResponse,
			"status", status, "bytes", len(body), "latency_ms", time.Since(start).Milliseconds())
		s.writeAuditWithBody(req, decision, bodyBuf, status, 0, time.Since(start), "", "")
		return nil
	}

	// Allow: dial origin under TLS with verification, forward.
	// Per-request upstream TLS dial. The debug record (visible under
	// `trollbridge run -v`) carries timing so an operator chasing a
	// timeout can attribute it to network setup vs. payload transfer.
	// Issue #33 audit.
	originAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: time.Duration(s.cfg.Forwarder.ConnectionAcquireTimeoutSeconds) * time.Second}
	dialStart := time.Now()
	originConn, err := tls.DialWithDialer(dialer, "tcp", originAddr, &tls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.originRoots,
	})
	dialMS := time.Since(dialStart).Milliseconds()
	var dialCategory TLSErrorCategory
	if err != nil {
		// Origin TLS dial failed — classify so an operator can
		// distinguish "upstream cert untrusted" from "host
		// unreachable" without parsing crypto/tls error strings.
		// The category also rides on the audit entry's
		// TLSErrorCategory field (#138).
		dialCategory = ClassifyOriginTLSError(err)
		rlog.Warn("upstream_dial",
			"phase", oplog.PhaseUpstreamDial,
			"event", oplog.EventInterceptUpstreamTLSFail,
			"ok", false,
			"duration_ms", dialMS,
			"tls_error_category", string(dialCategory),
			"sni", host,
			"error", err.Error(),
		)
	} else {
		rlog.Debug("upstream_dial",
			"phase", oplog.PhaseUpstreamDial,
			"ok", true,
			"duration_ms", dialMS,
		)
	}
	if err != nil {
		body := "trollbridge: origin TLS verification failed: " + err.Error()
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":      {"text/plain; charset=utf-8"},
				"Content-Length":    {strconv.Itoa(len(body))},
				"Trollbridge-Reason": {"origin-tls-failure"},
				HeaderRequestID:     {req.ID},
				"Connection":        {"close"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		_ = resp.Write(tlsConn)
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error(), string(dialCategory))
		return nil
	}
	defer originConn.Close()

	// Build outbound: copy the inbound request URL/headers/body.
	outbound := r.Clone(r.Context())
	outbound.URL.Scheme = "https"
	outbound.URL.Host = host
	stripHopByHop(outbound.Header)
	outbound.Header.Set("Via", strings.TrimSpace(outbound.Header.Get("Via")+" 1.1 trollbridge"))
	outbound.RequestURI = "" // client requests must have empty RequestURI
	if outbound.Body == nil && len(bodyBuf) > 0 {
		outbound.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		outbound.ContentLength = int64(len(bodyBuf))
	}

	// Write the request to the origin TLS connection directly.
	if err := outbound.Write(originConn); err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error(), "")
		return err
	}

	// Read the response from the origin and forward to the client.
	originBR := bufio.NewReader(originConn)
	resp, err := http.ReadResponse(originBR, outbound)
	if err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error(), "")
		return err
	}
	defer resp.Body.Close()

	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Header.Set(HeaderRequestID, req.ID)

	if err := resp.Write(tlsConn); err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, resp.StatusCode, 0, time.Since(start), err.Error(), "")
		return err
	}
	rlog.Debug("response", "phase", oplog.PhaseResponse,
		"status", resp.StatusCode, "bytes", resp.ContentLength, "latency_ms", time.Since(start).Milliseconds())
	s.writeAuditWithBody(req, decision, bodyBuf, resp.StatusCode, resp.ContentLength, time.Since(start), "", "")
	return nil
}
