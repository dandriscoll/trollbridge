// Package server is the top-level glue: listen, dispatch, decide,
// forward, audit. See DESIGN.md §4.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/identity"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/types"

	"github.com/google/uuid"
)

// Version is set at build time via -ldflags="-X ...".
var Version = "0.1.0-dev"

// Server holds the long-lived state of a running drawbridge.
type Server struct {
	cfg      *config.Config
	engine   *policy.Engine
	identity *identity.Resolver
	audit    *audit.Logger
	httpSrv  *http.Server

	transport *http.Transport
	logger    *log.Logger

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// New constructs a Server from a loaded config and engine.
func New(cfg *config.Config, engine *policy.Engine) (*Server, error) {
	auditLogger, err := audit.New(
		cfg.Logging.AuditPath,
		cfg.Logging.AuditBufferSize,
		audit.OverflowMode(cfg.Logging.AuditOverflow),
	)
	if err != nil {
		return nil, err
	}
	return NewWithAudit(cfg, engine, auditLogger)
}

// NewWithAudit constructs a Server using a pre-built audit logger.
// Tests use this to inject a logger pointing at a tmp file.
func NewWithAudit(cfg *config.Config, engine *policy.Engine, auditLogger *audit.Logger) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		engine:   engine,
		identity: identity.New(cfg.Identities),
		audit:    auditLogger,
		logger:   log.New(os.Stderr, "drawbridge: ", log.LstdFlags),
		conns:    map[net.Conn]struct{}{},
	}
	s.transport = &http.Transport{
		MaxIdleConns:        cfg.Forwarder.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Forwarder.MaxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}
	s.httpSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Listen.Address, strconv.Itoa(cfg.Listen.Port)),
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
	}
	return s, nil
}

// ListenAndServe starts the listener loop and blocks until ctx is
// cancelled or the server stops.
func (s *Server) ListenAndServe(ctx context.Context) error {
	go s.shutdownOnContext(ctx)
	err := s.httpSrv.ListenAndServe()
	return s.finishServe(err)
}

// ServeOnListener runs the proxy on a pre-bound listener (used in
// tests so we don't fight for ports).
func (s *Server) ServeOnListener(ctx context.Context, ln net.Listener) error {
	go s.shutdownOnContext(ctx)
	err := s.httpSrv.Serve(ln)
	return s.finishServe(err)
}

func (s *Server) shutdownOnContext(ctx context.Context) {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(s.cfg.Shutdown.GraceSeconds)*time.Second,
	)
	defer cancel()
	_ = s.httpSrv.Shutdown(shutdownCtx)
	// Hijacked CONNECT connections aren't tracked by http.Server;
	// close them so pipeBidir returns and audit-log writes complete.
	s.closeTrackedConns()
}

func (s *Server) finishServe(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	// Wait briefly for in-flight pipeBidir goroutines to land
	// their final audit writes before flushing the audit log.
	s.waitForConns(2 * time.Second)
	if cerr := s.audit.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

func (s *Server) trackConn(c net.Conn) {
	s.connsMu.Lock()
	s.conns[c] = struct{}{}
	s.connsMu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

func (s *Server) closeTrackedConns() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) waitForConns(deadline time.Duration) {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		s.connsMu.Lock()
		n := len(s.conns)
		s.connsMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Addr returns the listen address (after resolution).
func (s *Server) Addr() string { return s.httpSrv.Addr }

// Engine exposes the underlying engine for SIGHUP reloads.
func (s *Server) Engine() *policy.Engine { return s.engine }

// serveHTTP dispatches CONNECT vs. plain HTTP.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()
	sessionID := uuid.NewString()
	identityID := s.identity.Resolve(r.RemoteAddr, r)

	host, port := splitHostPort(r.URL.Host, "80")
	req := &types.RequestEvent{
		ID:         requestID,
		SessionID:  sessionID,
		IdentityID: identityID,
		Timestamp:  start,
		Method:     r.Method,
		Scheme:     "http",
		Host:       host,
		Port:       port,
		Path:       r.URL.Path,
		Headers:    r.Header.Clone(),
		ClientAddr: r.RemoteAddr,
	}
	decision := s.engine.Decide(req)

	if decision.Effect != types.EffectAllow {
		s.refuseHTTP(w, req, decision, start)
		return
	}

	outbound, err := s.buildOutbound(r)
	if err != nil {
		s.logger.Printf("buildOutbound: %v", err)
		http.Error(w, "drawbridge: bad request", http.StatusBadRequest)
		s.writeAudit(req, decision, "", 0, http.StatusBadRequest, 0, time.Since(start), err.Error())
		return
	}
	resp, err := s.transport.RoundTrip(outbound)
	if err != nil {
		s.logger.Printf("forward: %v", err)
		http.Error(w, "drawbridge: upstream error: "+err.Error(), http.StatusBadGateway)
		s.writeAudit(req, decision, "", 0, http.StatusBadGateway, 0, time.Since(start), err.Error())
		return
	}
	defer resp.Body.Close()

	_, redactedCount := redactHeadersForAudit(r.Header, decision.Modifiers)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Via", strings.TrimSpace(w.Header().Get("Via")+" 1.1 drawbridge"))
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)

	s.writeAudit(req, decision, "", redactedCount, resp.StatusCode, n, time.Since(start), "")
}

func (s *Server) refuseHTTP(w http.ResponseWriter, req *types.RequestEvent, d types.Decision, start time.Time) {
	w.Header().Set("Drawbridge-Reason", string(d.Effect)+": "+d.Reason)
	switch d.Effect {
	case types.EffectDeny:
		http.Error(w, "drawbridge: request denied: "+d.Reason, http.StatusForbidden)
	case types.EffectAskUser, types.EffectAskLLM:
		http.Error(w, "drawbridge: request requires approval (Phase 2 feature)", http.StatusNetworkAuthenticationRequired)
	default:
		http.Error(w, "drawbridge: request not allowed", http.StatusForbidden)
	}
	s.writeAudit(req, d, "", 0, statusFromEffect(d.Effect), 0, time.Since(start), "")
}

func (s *Server) buildOutbound(r *http.Request) (*http.Request, error) {
	target := r.URL
	if !target.IsAbs() {
		return nil, fmt.Errorf("relative-form request not supported")
	}
	out, err := http.NewRequest(r.Method, target.String(), r.Body)
	if err != nil {
		return nil, err
	}
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)
	out.Header.Set("Via", strings.TrimSpace(out.Header.Get("Via")+" 1.1 drawbridge"))
	return out, nil
}

func stripHopByHop(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			h.Del(name)
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Proxy-Authorization",
		"Proxy-Authenticate", "Keep-Alive", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
}

func redactHeadersForAudit(h http.Header, modifiers []string) (http.Header, int) {
	out := h.Clone()
	count := 0
	for _, m := range modifiers {
		switch m {
		case "redact_authorization_header":
			if out.Get("Authorization") != "" {
				out.Set("Authorization", "<redacted>")
				count++
			}
		case "redact_cookie":
			if out.Get("Cookie") != "" {
				out.Set("Cookie", "<redacted>")
				count++
			}
		}
	}
	if out.Get("Proxy-Authorization") != "" {
		out.Set("Proxy-Authorization", "<redacted>")
		count++
	}
	return out, count
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()
	sessionID := uuid.NewString()
	identityID := s.identity.Resolve(r.RemoteAddr, r)

	host, port := splitHostPort(r.RequestURI, "443")
	req := &types.RequestEvent{
		ID:         requestID,
		SessionID:  sessionID,
		IdentityID: identityID,
		Timestamp:  start,
		Method:     "CONNECT",
		Scheme:     "https-tunneled",
		Host:       host,
		Port:       port,
		Path:       "",
		Headers:    r.Header.Clone(),
		ClientAddr: r.RemoteAddr,
	}
	decision := s.engine.Decide(req)
	if decision.Effect != types.EffectAllow {
		w.Header().Set("Drawbridge-Reason", string(decision.Effect)+": "+decision.Reason)
		http.Error(w, "drawbridge: CONNECT denied: "+decision.Reason, http.StatusForbidden)
		s.writeAudit(req, decision, "", 0, http.StatusForbidden, 0, time.Since(start), "")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "drawbridge: hijacking not supported", http.StatusInternalServerError)
		s.writeAudit(req, decision, "", 0, http.StatusInternalServerError, 0, time.Since(start), "no hijacker")
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		time.Duration(s.cfg.Forwarder.ConnectionAcquireTimeoutSeconds)*time.Second)
	if err != nil {
		http.Error(w, "drawbridge: upstream dial failed: "+err.Error(), http.StatusBadGateway)
		s.writeAudit(req, decision, "", 0, http.StatusBadGateway, 0, time.Since(start), err.Error())
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		s.writeAudit(req, decision, "", 0, http.StatusInternalServerError, 0, time.Since(start), err.Error())
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		upstream.Close()
		s.writeAudit(req, decision, "", 0, 0, 0, time.Since(start), err.Error())
		return
	}

	s.trackConn(clientConn)
	s.trackConn(upstream)
	defer s.untrackConn(clientConn)
	defer s.untrackConn(upstream)

	bytesIn, bytesOut := pipeBidir(clientConn, upstream)
	s.writeAudit(req, decision, "", 0, http.StatusOK, bytesIn+bytesOut, time.Since(start), "")
}

func pipeBidir(a, b net.Conn) (int64, int64) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	var ab, ba int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		ab, _ = io.Copy(b, a)
		_ = setReadDeadlineNow(b)
	}()
	go func() {
		defer wg.Done()
		ba, _ = io.Copy(a, b)
		_ = setReadDeadlineNow(a)
	}()
	wg.Wait()
	return ab, ba
}

func setReadDeadlineNow(c net.Conn) error {
	if d, ok := c.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(time.Now())
	}
	return nil
}

func (s *Server) writeAudit(req *types.RequestEvent, d types.Decision, queryRedacted string, redactedCount int, status int, size int64, latency time.Duration, errStr string) {
	entry := audit.Entry{
		DrawbridgeVersion:    Version,
		AuditSchemaVersion:   1,
		RequestID:            req.ID,
		SessionID:            req.SessionID,
		IdentityID:           req.IdentityID,
		ClientAddr:           req.ClientAddr,
		Method:               req.Method,
		Scheme:               req.Scheme,
		Host:                 req.Host,
		Port:                 req.Port,
		Path:                 req.Path,
		QueryRedacted:        queryRedacted,
		Decision:             string(d.Effect),
		DecisionSource:       string(d.Source),
		RuleID:               d.RuleID,
		RuleSetVersion:       s.engine.RuleSetVersion(),
		LLMAdvisorID:         d.AdvisorID,
		LLMConfidence:        "n/a",
		LLMInputHash:         "",
		Reason:               d.Reason,
		RedactionApplied:     redactedCount > 0,
		RedactedFieldCount:   redactedCount,
		BodyInspectionStatus: "not_required",
		RequestBodySample:    "",
		ResponseStatus:       status,
		ResponseSizeBytes:    size,
		LatencyMS:            latency.Milliseconds(),
		Error:                errStr,
	}
	if err := s.audit.Write(entry); err != nil {
		s.logger.Printf("audit write: %v", err)
	}
}

func splitHostPort(hostport, defaultPort string) (string, int) {
	if hostport == "" {
		p, _ := strconv.Atoi(defaultPort)
		return "", p
	}
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		if u, perr := url.Parse(hostport); perr == nil && u.Host != "" && u.Host != hostport {
			return splitHostPort(u.Host, defaultPort)
		}
		p, _ := strconv.Atoi(defaultPort)
		return hostport, p
	}
	pi, _ := strconv.Atoi(p)
	return h, pi
}

func statusFromEffect(e types.Effect) int {
	switch e {
	case types.EffectDeny:
		return http.StatusForbidden
	case types.EffectAskUser, types.EffectAskLLM:
		return http.StatusNetworkAuthenticationRequired
	}
	return http.StatusOK
}

// silence imports we may not use in some build configs.
var _ = config.Config{}
