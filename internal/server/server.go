// Package server is the top-level glue: listen, dispatch, decide,
// forward, audit. See DESIGN.md §4.
package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/drawbridge/internal/advisor"
	"github.com/dandriscoll/drawbridge/internal/approvals"
	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/ca"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/control"
	"github.com/dandriscoll/drawbridge/internal/hostlist"
	"github.com/dandriscoll/drawbridge/internal/identity"
	"github.com/dandriscoll/drawbridge/internal/oplog"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/redact"
	"github.com/dandriscoll/drawbridge/internal/sessions"
	"github.com/dandriscoll/drawbridge/internal/types"

	"github.com/google/uuid"
)

// Version is set at build time via -ldflags="-X ...".
var Version = "0.2.0-dev"

// Server holds the long-lived state of a running drawbridge.
type Server struct {
	cfg      *config.Config
	engine   *policy.Engine
	identity *identity.Resolver
	audit    *audit.Logger
	httpSrv  *http.Server

	queue    *approvals.Queue
	sessions *sessions.Tracker
	control  *control.Server

	ca           *ca.CA
	originRoots  *x509.CertPool
	redactor     *redact.Config
	advisor      *advisor.Service

	allowList *hostlist.HostList
	denyList  *hostlist.HostList

	listsMu      sync.Mutex

	transport *http.Transport
	opLog     *slog.Logger

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	// MaxBodySampleBytes caps how much request body we read for
	// body_pattern matching on plain HTTP. 0 disables.
	MaxBodySampleBytes int

	rootCtx context.Context
}

// New constructs a Server from a loaded config and engine. The
// operational logger is built from cfg.Logging.OperationalPath at
// the default Info level. For finer control (level, sink, test
// capture) use NewWithLoggers.
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

// NewWithAudit constructs a Server using a pre-built audit logger
// and a default Info-level operational logger writing to whatever
// cfg.Logging.OperationalPath points at.
func NewWithAudit(cfg *config.Config, engine *policy.Engine, auditLogger *audit.Logger) (*Server, error) {
	opLog, err := oplog.New(cfg.Logging.OperationalPath, nil)
	if err != nil {
		return nil, err
	}
	auditLogger.SetOpLog(opLog)
	return NewWithLoggers(cfg, engine, auditLogger, opLog)
}

// NewWithLoggers constructs a Server using a pre-built audit logger
// and a pre-built operational *slog.Logger. Tests use this to
// capture operational lines into a buffer-handler.
func NewWithLoggers(cfg *config.Config, engine *policy.Engine, auditLogger *audit.Logger, opLog *slog.Logger) (*Server, error) {
	if opLog == nil {
		var err error
		opLog, err = oplog.New(oplog.StderrSink, nil)
		if err != nil {
			return nil, err
		}
	}
	q := approvals.New(
		cfg.Approvals.MaxPending,
		time.Duration(cfg.Approvals.TimeoutSeconds)*time.Second,
		cfg.Approvals.OnTimeout,
	)
	t := sessions.New()
	s := &Server{
		cfg:      cfg,
		engine:   engine,
		identity: identity.New(cfg.Identities),
		audit:    auditLogger,
		opLog:    opLog,
		conns:    map[net.Conn]struct{}{},
		queue:    q,
		sessions: t,
		control: func() *control.Server {
			addr := ""
			if cfg.Ports.Control != 0 {
				addr = cfg.BindAddr(cfg.Ports.Control)
			}
			c := control.New(addr, q, t, engine)
			c.SetOpLog(opLog)
			return c
		}(),
		MaxBodySampleBytes: 1 << 20, // 1 MiB
	}
	// Build the redactor config from cfg.Redaction.
	redactorJSONPaths := []string{}
	redactorBodyRegexes := []string{}
	for _, br := range cfg.Redaction.BodyRedactors {
		if br.JSONPath != "" {
			redactorJSONPaths = append(redactorJSONPaths, br.JSONPath)
		}
		if br.Regex != "" {
			redactorBodyRegexes = append(redactorBodyRegexes, br.Regex)
		}
	}
	queryRegexes := []string{}
	for _, qr := range cfg.Redaction.QueryRedactors {
		queryRegexes = append(queryRegexes, qr.Regex)
	}
	rcfg, err := redact.Compile(redactorJSONPaths, redactorBodyRegexes, queryRegexes, cfg.Redaction.DefaultModifiers)
	if err != nil {
		return nil, fmt.Errorf("redaction compile: %w", err)
	}
	s.redactor = rcfg

	// Load the CA. The CA is needed in two places:
	//   - TLS interception (when cfg.Interception.Enabled)
	//   - mTLS controller (when cfg.Ports.Control != 0)
	// If either is in use, the CA must load successfully.
	caRequired := cfg.Interception.Enabled || cfg.Ports.Control != 0
	if caRequired {
		ttl := time.Duration(cfg.Interception.LeafCertTTLHours) * time.Hour
		caObj, err := ca.Load(
			cfg.Interception.CA.CertPath,
			cfg.Interception.CA.KeyPath,
			ca.KeyType(cfg.Interception.LeafKeyType),
			ttl,
		)
		if err != nil {
			return nil, fmt.Errorf("CA load failed (required for %s): %w; fix: run `drawbridge ca init`",
				caRequiredReason(cfg.Interception.Enabled, cfg.Ports.Control != 0), err)
		}
		if cfg.Interception.Enabled {
			s.ca = caObj
		}
		s.control.SetCA(caObj)
		s.control.SetTLS(caObj)
	}
	roots, err := buildOriginRoots(cfg.Interception.OriginTrust)
	if err != nil {
		return nil, fmt.Errorf("origin trust: %w", err)
	}
	s.originRoots = roots

	// Initialize advisor service. Provider can be nil (disabled).
	advCfg := advisor.Config{
		Enabled:         cfg.LLM.Enabled,
		ConfidenceFloor: cfg.LLM.ConfidenceFloor,
		OnUnavailable:   cfg.LLM.OnUnavailable,
		CacheTTL:        time.Duration(cfg.LLM.CacheTTLSeconds) * time.Second,
		Timeout:         time.Duration(cfg.LLM.TimeoutSeconds) * time.Second,
		KnownModifiers:  modifierSetForAdvisor(),
		Directives:      cfg.LLM.Directives,
	}
	var prov advisor.Provider
	if cfg.LLM.Enabled {
		// Default provider: HTTPClassifier pointing at the
		// configured endpoint. Operators wiring Anthropic-shaped
		// endpoints can swap the JSON shape on the receiving end.
		apiKey := ""
		if cfg.LLM.APIKeyPath != "" {
			if data, err := os.ReadFile(cfg.LLM.APIKeyPath); err == nil {
				apiKey = strings.TrimSpace(string(data))
			}
		}
		prov = &advisor.HTTPClassifier{
			Endpoint: cfg.LLM.Endpoint,
			APIKey:   apiKey,
		}
	}
	s.advisor = advisor.New(advCfg, prov)
	s.transport = &http.Transport{
		MaxIdleConns:        cfg.Forwarder.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Forwarder.MaxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}
	s.httpSrv = &http.Server{
		Addr:              cfg.BindAddr(cfg.Ports.Proxy),
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				if s.sessions != nil {
					s.sessions.Drop(c.RemoteAddr().String())
				}
			}
		},
	}
	return s, nil
}

// ListenAndServe starts the listener loop and blocks until ctx is
// cancelled or the server stops.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.rootCtx = ctx
	if _, err := s.control.ListenAndServe(ctx); err != nil {
		return err
	}
	go s.shutdownOnContext(ctx)
	err := s.httpSrv.ListenAndServe()
	return s.finishServe(err)
}

// ServeOnListener runs the proxy on a pre-bound listener (used in
// tests so we don't fight for ports).
func (s *Server) ServeOnListener(ctx context.Context, ln net.Listener) error {
	s.rootCtx = ctx
	if _, err := s.control.ListenAndServe(ctx); err != nil {
		return err
	}
	go s.shutdownOnContext(ctx)
	err := s.httpSrv.Serve(ln)
	return s.finishServe(err)
}

// ControlAddr returns the bound control-plane address. Useful to
// know in tests that pass `:0`.
func (s *Server) ControlAddr() string {
	if s.control == nil {
		return ""
	}
	if s.cfg.Ports.Control == 0 {
		return ""
	}
	return s.cfg.BindAddr(s.cfg.Ports.Control)
}

// caRequiredReason returns a short string for error messages
// explaining why the CA had to load.
func caRequiredReason(intercept, controller bool) string {
	switch {
	case intercept && controller:
		return "TLS interception + mTLS controller"
	case intercept:
		return "TLS interception"
	default:
		return "mTLS controller"
	}
}

// Queue returns the approvals queue (for tests / introspection).
func (s *Server) Queue() *approvals.Queue { return s.queue }

// SessionsTracker returns the per-client session tracker.
func (s *Server) SessionsTracker() *sessions.Tracker { return s.sessions }

// Sessions returns the session tracker.
func (s *Server) Sessions() *sessions.Tracker { return s.sessions }

func (s *Server) shutdownOnContext(ctx context.Context) {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(s.cfg.Shutdown.GraceSeconds)*time.Second,
	)
	defer cancel()
	// Resolve held approvals as deny so blocked dispatcher
	// goroutines exit promptly.
	if s.queue != nil {
		s.queue.Shutdown()
	}
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
	identityID := s.identity.Resolve(r.RemoteAddr, r)
	sess := s.sessions.GetOrCreate(r.RemoteAddr, identityID)

	host, port := splitHostPort(r.URL.Host, "80")
	rlog := s.opLog.With(
		"request_id", requestID,
		"identity", identityID,
		"method", r.Method,
		"scheme", "http",
		"host", host,
		"port", port,
	)
	rlog.Debug("received", "phase", oplog.PhaseReceived, "path", r.URL.Path)
	req := &types.RequestEvent{
		ID:         requestID,
		SessionID:  sess.ID,
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

	// Capture a bounded body sample for body_pattern matching.
	// Plain HTTP only; HTTPS body inspection arrives Phase 3.
	// Over-cap bodies forward in full via MultiReader so we do
	// not silently truncate large uploads; the sample is dropped
	// instead, and the engine fails closed on body-required
	// rules.
	var bodyBuf []byte
	if r.Body != nil && s.MaxBodySampleBytes > 0 && bodyMethodNeedsSample(r.Method) {
		prefix, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxBodySampleBytes)+1))
		if err != nil {
			http.Error(w, "drawbridge: body read failed", http.StatusBadRequest)
			s.writeAudit(req, types.Decision{Effect: types.EffectDeny, Source: types.SourceDefault, Reason: "body read failed: " + err.Error()},
				"", 0, http.StatusBadRequest, 0, time.Since(start), err.Error())
			return
		}
		if int64(len(prefix)) > int64(s.MaxBodySampleBytes) {
			req.BodyAvailable = false
			req.BodySize = int64(len(prefix))
			req.BodySample = nil
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
		} else {
			req.BodyAvailable = true
			req.BodySize = int64(len(prefix))
			req.BodySample = prefix
			bodyBuf = prefix
			r.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		}
	}

	// Fast path: evaluate flat allow/deny lists BEFORE the rule
	// engine and BEFORE the advisor. A match here short-circuits.
	decision, fastHit := s.fastPathDecide("http", host, port, req.Path)
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

	// Approval queue: if engine returned ask_user (or ask_llm with
	// no advisor configured in this phase), hold the request.
	if decision.Effect == types.EffectAskUser || decision.Effect == types.EffectAskLLM {
		rlog.Debug("held", "phase", oplog.PhaseHeld, "effect", string(decision.Effect))
		decision = s.holdAndWait(req, decision)
		rlog.Debug("resolved", "phase", oplog.PhaseResolved, "effect", string(decision.Effect))
	}

	// History records the resolved decision.
	s.engine.History().Record(req, decision, time.Now().UTC())

	switch decision.Effect {
	case types.EffectAllow, types.EffectAskUserResolvedAllow:
		// allowed: forward
	default:
		// deny / ask_user_resolved_deny / ask_user_timed_out
		s.refuseHTTP(w, req, decision, start)
		return
	}

	outbound, err := s.buildOutbound(r)
	if err != nil {
		rlog.Error("bad request", "event", oplog.EventBadRequest, "error", err.Error())
		http.Error(w, "drawbridge: bad request", http.StatusBadRequest)
		s.writeAudit(req, decision, "", 0, http.StatusBadRequest, 0, time.Since(start), err.Error())
		return
	}
	resp, err := s.transport.RoundTrip(outbound)
	if err != nil {
		rlog.Error("forward error", "event", oplog.EventForwardError, "error", err.Error())
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

	rlog.Debug("response", "phase", oplog.PhaseResponse,
		"status", resp.StatusCode, "bytes", n, "latency_ms", time.Since(start).Milliseconds())
	s.writeAudit(req, decision, "", redactedCount, resp.StatusCode, n, time.Since(start), "")
}

// holdAndWait routes ask_llm decisions through the advisor first;
// if the advisor's resolved effect is allow/deny, return it. If
// the advisor falls back to ask_user (or we're handling an
// ask_user rule directly), enqueue and block.
//
// As a side effect, when the advisor is consulted, the request's
// `Headers` map gets a transient `X-Drawbridge-LLM-Input-Hash`
// entry the audit-write path strips back out and stores in
// `llm_input_hash`. This couples advisor input to the audit
// record without threading a side-channel.
func (s *Server) holdAndWait(req *types.RequestEvent, base types.Decision) types.Decision {
	if base.Effect == types.EffectAskLLM && s.advisor != nil {
		ctx := s.rootCtx
		if ctx == nil {
			ctx = context.Background()
		}
		hdrs := map[string]string{}
		for k := range req.Headers {
			v := req.Headers.Get(k)
			switch strings.ToLower(k) {
			case "authorization", "cookie", "proxy-authorization":
				hdrs[k] = "<redacted>"
			default:
				hdrs[k] = v
			}
		}
		// Build read-only list context the advisor sees as input.
		// The advisor MAY recommend actions based on these; the
		// advisor MUST NOT mutate them. List mutation is human-
		// only (console + manual file edits).
		lists := &advisor.ListContext{
			Allow: rawPatterns(s.AllowList()),
			Deny:  rawPatterns(s.DenyList()),
		}
		// Build the same Input the advisor sees, hash it, stash on
		// the request so the audit-write path can record it.
		input := advisor.Input{
			Method: req.Method, Scheme: req.Scheme, Host: req.Host, Port: req.Port,
			Path: req.Path, HeadersRedacted: hdrs, Identity: req.IdentityID,
			RuleSetVersion: s.engine.RuleSetVersion(),
			AllowList:      lists.Allow,
			DenyList:       lists.Deny,
		}
		req.Headers.Set("X-Drawbridge-LLM-Input-Hash", advisor.CanonicalizeInput(input))

		d, _ := s.advisor.Classify(ctx, req, s.engine.RuleSetVersion(), nil, hdrs, lists)
		if d.Effect == types.EffectAllow || d.Effect == types.EffectDeny {
			return d
		}
		// Advisor said ask_user (or fell back). Continue to queue.
		base = d
	}
	id, ch, err := s.queue.Enqueue(req, base)
	if err != nil {
		return types.Decision{
			Effect: types.EffectAskUserResolvedDeny,
			Source: types.SourceApprovalQueue,
			Reason: "approval queue full: " + err.Error(),
		}
	}
	ctx := s.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return s.queue.Wait(ctx, id, ch)
}

// bodyMethodNeedsSample decides whether to capture a body sample
// for the given method.
func bodyMethodNeedsSample(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func (s *Server) refuseHTTP(w http.ResponseWriter, req *types.RequestEvent, d types.Decision, start time.Time) {
	w.Header().Set("Drawbridge-Reason", string(d.Effect)+": "+d.Reason)
	switch d.Effect {
	case types.EffectDeny, types.EffectAskUserResolvedDeny, types.EffectAskUserTimedOut:
		http.Error(w, "drawbridge: request denied: "+d.Reason, http.StatusForbidden)
	case types.EffectAskUser, types.EffectAskLLM:
		// Should not reach here; holdAndWait converts these.
		http.Error(w, "drawbridge: request requires approval", http.StatusNetworkAuthenticationRequired)
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
		// drawbridge-internal hint headers MUST NOT leak to origins.
		"X-Drawbridge-LLM-Input-Hash",
		"X-Original-Query",
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
	identityID := s.identity.Resolve(r.RemoteAddr, r)
	sess := s.sessions.GetOrCreate(r.RemoteAddr, identityID)

	host, port := splitHostPort(r.RequestURI, "443")
	req := &types.RequestEvent{
		ID:         requestID,
		SessionID:  sess.ID,
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
	// CONNECT only carries host:port, no path. Use "/" as the
	// path for fast-path matching; only patterns with no path or
	// path "/" or path-prefix can fire here. Scheme is unknown at
	// CONNECT time; only patterns with no scheme constraint match.
	decision, fastHit := s.fastPathDecide("", host, port, "/")
	if !fastHit {
		decision = s.engine.Decide(req)
	}
	if decision.Effect == types.EffectAskUser || decision.Effect == types.EffectAskLLM {
		decision = s.holdAndWait(req, decision)
	}
	s.engine.History().Record(req, decision, time.Now().UTC())
	if !(decision.Effect == types.EffectAllow || decision.Effect == types.EffectAskUserResolvedAllow) {
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
	defer s.untrackConn(clientConn)

	if s.shouldIntercept(host) {
		// Phase 3: terminate TLS, dispatch per-request.
		upstream.Close() // we'll dial upstream per-request
		s.writeAudit(req, decision, "", 0, http.StatusOK, 0, time.Since(start), "")
		_ = s.interceptCONNECT(clientConn, host, port, sess.ID, identityID)
		return
	}

	s.trackConn(upstream)
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

// writeAuditWithBody is like writeAudit but also redacts and stores a
// body sample (used by the interception path).
func (s *Server) writeAuditWithBody(req *types.RequestEvent, d types.Decision, body []byte, status int, size int64, latency time.Duration, errStr string) {
	llmInputHash := req.Headers.Get("X-Drawbridge-LLM-Input-Hash")
	queryRedacted, _ := s.redactor.Query(req.Headers.Get("X-Original-Query"))
	headers, headerCount := s.redactor.Headers(req.Headers, d.Modifiers)
	_ = headers
	bodyRes := s.redactor.Body(body, req.Headers.Get("Content-Type"))
	sample, truncated := redact.SampleForAudit(bodyRes.Output, 4096)
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
		LLMInputHash:         llmInputHash,
		Reason:               d.Reason,
		RedactionApplied:     headerCount+bodyRes.RedactedFields > 0,
		RedactedFieldCount:   headerCount + bodyRes.RedactedFields,
		BodyInspectionStatus: inspectionStatus(len(body) > 0, truncated),
		RequestBodySample:    string(sample),
		ResponseStatus:       status,
		ResponseSizeBytes:    size,
		LatencyMS:            latency.Milliseconds(),
		Error:                errStr,
	}
	if err := s.audit.Write(entry); err != nil {
		s.opLog.Warn("audit write failure",
			"event", oplog.EventAuditWriteFailure,
			"request_id", req.ID, "error", err.Error())
	}
}

func inspectionStatus(hasBody, truncated bool) string {
	if !hasBody {
		return "not_required"
	}
	if truncated {
		return "truncated"
	}
	return "inspected"
}

func (s *Server) writeAudit(req *types.RequestEvent, d types.Decision, queryRedacted string, redactedCount int, status int, size int64, latency time.Duration, errStr string) {
	llmInputHash := req.Headers.Get("X-Drawbridge-LLM-Input-Hash")
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
		LLMInputHash:         llmInputHash,
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
		s.opLog.Warn("audit write failure",
			"event", oplog.EventAuditWriteFailure,
			"request_id", req.ID, "error", err.Error())
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

// rawPatterns returns the raw line text of every pattern on the
// supplied list. Used to surface lists to the advisor as input.
func rawPatterns(h *hostlist.HostList) []string {
	if h == nil {
		return nil
	}
	out := make([]string, 0, len(h.Patterns))
	for _, p := range h.Patterns {
		out = append(out, p.Raw)
	}
	return out
}

// modifierSetForAdvisor returns the names of modifiers the advisor
// is allowed to recommend. We accept the same set the engine knows.
func modifierSetForAdvisor() map[string]bool {
	out := map[string]bool{}
	for _, m := range policy.KnownModifiers() {
		out[m] = true
	}
	return out
}

// buildOriginRoots resolves the configured origin-trust mode into a
// concrete x509 cert pool.
func buildOriginRoots(t config.OriginTrust) (*x509.CertPool, error) {
	mode := t.Mode
	if mode == "" {
		mode = "system"
	}
	var pool *x509.CertPool
	switch mode {
	case "system":
		p, err := x509.SystemCertPool()
		if err != nil || p == nil {
			p = x509.NewCertPool()
		}
		pool = p
	case "file":
		pool = x509.NewCertPool()
		if err := appendFileToPool(pool, t.Path); err != nil {
			return nil, err
		}
	case "mixed":
		p, err := x509.SystemCertPool()
		if err != nil || p == nil {
			p = x509.NewCertPool()
		}
		if err := appendFileToPool(p, t.Path); err != nil {
			return nil, err
		}
		pool = p
	default:
		return nil, fmt.Errorf("unknown origin_trust.mode %q (want system|file|mixed)", mode)
	}
	return pool, nil
}

func appendFileToPool(p *x509.CertPool, path string) error {
	if path == "" {
		return fmt.Errorf("origin_trust.path is required when mode is file or mixed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !p.AppendCertsFromPEM(data) {
		return fmt.Errorf("no PEM certs found in %s", path)
	}
	return nil
}

// SetHostLists wires the parsed allow / deny lists. Either may be
// nil. Lists are evaluated BEFORE the rule engine and BEFORE the
// LLM advisor — a match short-circuits the pipeline.
func (s *Server) SetHostLists(allow, deny *hostlist.HostList) {
	s.listsMu.Lock()
	s.allowList = allow
	s.denyList = deny
	s.listsMu.Unlock()
}

// AllowList returns the current allowlist (used by the advisor
// input builder; safe under concurrent reload).
func (s *Server) AllowList() *hostlist.HostList {
	s.listsMu.Lock()
	defer s.listsMu.Unlock()
	return s.allowList
}

// DenyList returns the current denylist.
func (s *Server) DenyList() *hostlist.HostList {
	s.listsMu.Lock()
	defer s.listsMu.Unlock()
	return s.denyList
}

// SetLists installs the inline allow/deny patterns parsed from
// drawbridge.yaml's `lists.allow` / `lists.deny`.
func (s *Server) SetLists(allow, deny []string) error {
	a, err := hostlist.LoadInline("allow", "drawbridge.yaml:lists.allow", allow)
	if err != nil {
		return err
	}
	d, err := hostlist.LoadInline("deny", "drawbridge.yaml:lists.deny", deny)
	if err != nil {
		return err
	}
	s.listsMu.Lock()
	s.allowList = a
	s.denyList = d
	s.listsMu.Unlock()
	return nil
}

// ReloadListsFromConfig re-parses the cfg's inline lists into the
// in-memory matcher. Called by the console REPL after it writes a
// new entry into the yaml file.
func (s *Server) ReloadListsFromConfig(cfg *config.Config) error {
	if err := s.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
		s.opLog.Error("list reload failed",
			"event", oplog.EventAllowlistReloadFailure, "error", err.Error())
		return err
	}
	s.opLog.Info("lists reloaded",
		"event", oplog.EventAllowlistReload,
		"allow_patterns", len(s.AllowList().Patterns),
		"deny_patterns", len(s.DenyList().Patterns))
	return nil
}

// fastPathDecide returns a Decision (and true) when the request
// matches the deny list (deny wins) or the allow list. Returns
// (zero Decision, false) when no list matches and the engine
// should run. Pass scheme="" for CONNECT (pre-intercept), "http"
// for plaintext, "https" for intercepted HTTPS.
func (s *Server) fastPathDecide(scheme, host string, port int, path string) (types.Decision, bool) {
	allow, deny := s.AllowList(), s.DenyList()
	if pat, ok := deny.Match(scheme, host, port, path); ok {
		return types.Decision{
			Effect: types.EffectDeny,
			Source: types.SourceDenyList,
			RuleID: pat.Source,
			Reason: "matched deny list: " + pat.Raw,
		}, true
	}
	if pat, ok := allow.Match(scheme, host, port, path); ok {
		return types.Decision{
			Effect: types.EffectAllow,
			Source: types.SourceAllowList,
			RuleID: pat.Source,
			Reason: "matched allow list: " + pat.Raw,
		}, true
	}
	return types.Decision{}, false
}

// SetAdvisorProvider lets tests swap the advisor's underlying
// provider (e.g., a MockProvider).
func (s *Server) SetAdvisorProvider(p advisor.Provider) {
	advCfg := advisor.Config{
		Enabled:         true,
		ConfidenceFloor: s.cfg.LLM.ConfidenceFloor,
		OnUnavailable:   s.cfg.LLM.OnUnavailable,
		CacheTTL:        time.Duration(s.cfg.LLM.CacheTTLSeconds) * time.Second,
		Timeout:         time.Duration(s.cfg.LLM.TimeoutSeconds) * time.Second,
		KnownModifiers:  modifierSetForAdvisor(),
	}
	if advCfg.ConfidenceFloor == "" {
		advCfg.ConfidenceFloor = "medium"
	}
	if advCfg.OnUnavailable == "" {
		advCfg.OnUnavailable = "ask_user"
	}
	if advCfg.CacheTTL <= 0 {
		advCfg.CacheTTL = 5 * time.Minute
	}
	if advCfg.Timeout <= 0 {
		advCfg.Timeout = 8 * time.Second
	}
	s.advisor = advisor.New(advCfg, p)
}
