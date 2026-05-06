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

	"github.com/dandriscoll/drawbridge/internal/types"
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

// interceptCONNECT terminates the CONNECT tunnel as TLS, performs
// per-HTTP-request policy decisions on the inner stream, and
// proxies HTTP/1.1 to the origin under a verified TLS dial.
func (s *Server) interceptCONNECT(clientConn net.Conn, host string, port int, sessionID, identityID string) error {
	leaf, err := s.ca.LeafFor(host)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		// ALPN h1 only in Phase 3 — DESIGN.md §6.5.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Server(clientConn, tlsCfg)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls server handshake: %w", err)
	}

	br := bufio.NewReader(tlsConn)
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
				Source: types.SourceDefault,
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

		if err := s.dispatchInterceptedRequest(tlsConn, req, host, port, sessionID, identityID); err != nil {
			s.logger.Printf("intercepted request: %v", err)
			return err
		}
		// Connection: close → exit the loop.
		if strings.EqualFold(req.Header.Get("Connection"), "close") {
			return nil
		}
	}
}

func (s *Server) dispatchInterceptedRequest(tlsConn *tls.Conn, r *http.Request, host string, port int, sessionID, identityID string) error {
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

	decision := s.engine.Decide(req)
	if decision.Effect == types.EffectAskUser || decision.Effect == types.EffectAskLLM {
		decision = s.holdAndWait(req, decision)
	}
	s.engine.History().Record(req, decision, time.Now().UTC())

	if !(decision.Effect == types.EffectAllow || decision.Effect == types.EffectAskUserResolvedAllow) {
		// Refuse: 403 over the intercepted TLS connection.
		body := fmt.Sprintf("drawbridge: request denied: %s", decision.Reason)
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":      {"text/plain; charset=utf-8"},
				"Content-Length":    {strconv.Itoa(len(body))},
				"Drawbridge-Reason": {string(decision.Effect) + ": " + decision.Reason},
				"Connection":        {"close"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		_ = resp.Write(tlsConn)
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusForbidden, 0, time.Since(start), "")
		return nil
	}

	// Allow: dial origin under TLS with verification, forward.
	originAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: time.Duration(s.cfg.Forwarder.ConnectionAcquireTimeoutSeconds) * time.Second}
	originConn, err := tls.DialWithDialer(dialer, "tcp", originAddr, &tls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.originRoots,
	})
	if err != nil {
		body := "drawbridge: origin TLS verification failed: " + err.Error()
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":      {"text/plain; charset=utf-8"},
				"Content-Length":    {strconv.Itoa(len(body))},
				"Drawbridge-Reason": {"origin-tls-failure"},
				"Connection":        {"close"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		_ = resp.Write(tlsConn)
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error())
		return nil
	}
	defer originConn.Close()

	// Build outbound: copy the inbound request URL/headers/body.
	outbound := r.Clone(r.Context())
	outbound.URL.Scheme = "https"
	outbound.URL.Host = host
	stripHopByHop(outbound.Header)
	outbound.Header.Set("Via", strings.TrimSpace(outbound.Header.Get("Via")+" 1.1 drawbridge"))
	outbound.RequestURI = "" // client requests must have empty RequestURI
	if outbound.Body == nil && len(bodyBuf) > 0 {
		outbound.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		outbound.ContentLength = int64(len(bodyBuf))
	}

	// Write the request to the origin TLS connection directly.
	if err := outbound.Write(originConn); err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error())
		return err
	}

	// Read the response from the origin and forward to the client.
	originBR := bufio.NewReader(originConn)
	resp, err := http.ReadResponse(originBR, outbound)
	if err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, http.StatusBadGateway, 0, time.Since(start), err.Error())
		return err
	}
	defer resp.Body.Close()

	if err := resp.Write(tlsConn); err != nil {
		s.writeAuditWithBody(req, decision, bodyBuf, resp.StatusCode, 0, time.Since(start), err.Error())
		return err
	}
	s.writeAuditWithBody(req, decision, bodyBuf, resp.StatusCode, resp.ContentLength, time.Since(start), "")
	return nil
}
