// Package control implements trollbridge's HTTPS control plane (the
// approval API). It listens on the same adapter as the proxy, on
// `ports.control`, with mTLS enforced for every endpoint except
// `/v1/healthz`. Operator client certs are issued by the same CA
// that issues TLS-interception leaves (see `internal/ca`).
package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/opstream"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/sessions"
)

// CAOps is the subset of the CA package the control plane needs.
type CAOps interface {
	FlushCache()
	SHA256Fingerprint() string
}

// TLSProvider is what control needs from the CA to bring up an
// mTLS listener: a server cert and the trust roots for verifying
// operator client certs.
type TLSProvider interface {
	IssueServerCertFor(cn string, sans []string) (*tls.Certificate, error)
	ClientCAPool() *x509.CertPool
}

// ListsProvider exposes the daemon's current allow/deny lists to
// the control plane. Closes #99 part 1 (attach-mode TUI parity for
// the URLs pane). The /v1/lists endpoint reads from this provider
// at request time so the response reflects any hot-reloads since
// startup.
type ListsProvider interface {
	AllowPatterns() []string
	DenyPatterns() []string
}

// DigestsProvider exposes the advisor's digest ring to the control
// plane. Closes #99 part 2 (attach-mode TUI parity for the LLM
// panel). Returns nil when no advisor is configured.
type DigestsProvider interface {
	Digests() []advisor.Digest
}

// Server is the control-plane HTTPS listener.
type Server struct {
	addr     string
	queue    *approvals.Queue
	sessions *sessions.Tracker
	engine   *policy.Engine
	ops      *opstream.Ring
	lists    ListsProvider
	digests  DigestsProvider
	ca       CAOps
	tlsProv  TLSProvider
	srv      *http.Server

	opLog *slog.Logger
}

// SetOpLog wires the operational logger so that Serve errors land
// on the same stream the operator is tailing.
func (s *Server) SetOpLog(lg *slog.Logger) { s.opLog = lg }

// New constructs a Server bound to addr. addr must be a host:port
// string; addr=="" disables the control plane.
func New(addr string, q *approvals.Queue, t *sessions.Tracker, e *policy.Engine) *Server {
	return &Server{
		addr:     addr,
		queue:    q,
		sessions: t,
		engine:   e,
	}
}

// SetCA wires a CA into the control plane (post-construction so
// that interception-disabled deployments can still expose the
// other endpoints).
func (s *Server) SetCA(c CAOps) { s.ca = c }

// SetOps wires the operations ring exposed by /v1/ops. Safe to call
// before or after ListenAndServe.
func (s *Server) SetOps(r *opstream.Ring) { s.ops = r }

// SetLists wires the daemon's current allow/deny lists into the
// control plane so /v1/lists can return them. Closes #99 part 1.
func (s *Server) SetLists(p ListsProvider) { s.lists = p }

// SetDigests wires the advisor's digest ring into the control plane
// so /v1/llm-digests can return recent classifications. Closes #99
// part 2.
func (s *Server) SetDigests(p DigestsProvider) { s.digests = p }

// SetTLS wires the TLS-issuing provider used to bring up the mTLS
// listener.
func (s *Server) SetTLS(p TLSProvider) { s.tlsProv = p }

// ListenAndServe starts the control plane on addr; returns the
// concrete bound address (helpful when addr=":0").
func (s *Server) ListenAndServe(ctx context.Context) (string, error) {
	if s.addr == "" {
		return "", nil
	}
	if s.tlsProv == nil {
		return "", fmt.Errorf("control plane: TLS provider not configured (call SetTLS)")
	}

	host, _, err := net.SplitHostPort(s.addr)
	if err != nil {
		return "", fmt.Errorf("control plane: invalid addr %q: %w", s.addr, err)
	}
	sans := []string{"localhost", "127.0.0.1"}
	if host != "" && host != "0.0.0.0" && host != "127.0.0.1" && host != "localhost" {
		sans = append(sans, host)
	}
	serverCert, err := s.tlsProv.IssueServerCertFor("trollbridge-controller", sans)
	if err != nil {
		return "", fmt.Errorf("control plane: issue server cert: %w", err)
	}
	pool := s.tlsProv.ClientCAPool()
	if pool == nil {
		return "", fmt.Errorf("control plane: client CA pool is empty")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		// VerifyClientCertIfGiven lets /v1/healthz be reachable
		// without a client cert; per-endpoint requireClientCert
		// middleware enforces presence on every other endpoint.
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", s.addr, tlsCfg)
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	authd := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !verified(r) {
				http.Error(w, "client certificate required", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/v1/holds", authd(s.listHolds))
	mux.HandleFunc("/v1/holds/", authd(s.holdAction)) // /v1/holds/<id>/approve|deny
	mux.HandleFunc("/v1/ops", authd(s.listOps))
	mux.HandleFunc("/v1/lists", authd(s.listLists))             // closes #99 part 1
	mux.HandleFunc("/v1/llm-digests", authd(s.listLLMDigests))  // closes #99 part 2
	mux.HandleFunc("/v1/sessions", authd(s.listSessions))
	mux.HandleFunc("/v1/rules", authd(s.rulesInfo))
	mux.HandleFunc("/v1/rules/reload", authd(s.rulesReload))
	// /v1/healthz is intentionally unauthenticated for monitoring.
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/v1/ca/flush-cache", authd(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.ca == nil {
			http.Error(w, "interception is not enabled; nothing to flush", http.StatusBadRequest)
			return
		}
		s.ca.FlushCache()
		writeJSON(w, map[string]string{"status": "flushed", "ca_fingerprint": s.ca.SHA256Fingerprint()})
	}))
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	go func() {
		err := s.srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			if s.opLog != nil {
				s.opLog.Error("control plane error",
					"event", "control_plane_error", "error", err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "trollbridge: control plane error: %v\n", err)
			}
		}
	}()
	return ln.Addr().String(), nil
}

// verified is true when the connection presented a client cert that
// chains to a CA in the configured pool.
func verified(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}
	return len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0
}

func (s *Server) listHolds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.queue.Pending())
}

// listOps returns the in-memory operations ring snapshot. The TUI
// polls this on every refresh tick to render the upper pane (closes
// #52). Returns an empty array when no ring is configured.
func (s *Server) listOps(w http.ResponseWriter, r *http.Request) {
	if s.ops == nil {
		writeJSON(w, []opstream.Op{})
		return
	}
	writeJSON(w, s.ops.Snapshot())
}

// /v1/holds/<id>/approve  POST {"scope": "once"}
// /v1/holds/<id>/deny     POST {"reason": "..."}
func (s *Server) holdAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/holds/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "bad path; expected /v1/holds/<id>/approve|deny", http.StatusBadRequest)
		return
	}
	id, action := parts[0], parts[1]

	var body struct {
		Scope  string `json:"scope"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	switch action {
	case "approve":
		if !s.queue.Approve(id, body.Scope, "attach") {
			http.Error(w, "hold not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "approved", "id": id, "scope": body.Scope})
	case "deny":
		if !s.queue.Deny(id, body.Reason, "attach") {
			http.Error(w, "hold not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "denied", "id": id})
	default:
		http.Error(w, "unknown action; expected approve|deny", http.StatusBadRequest)
	}
}

// listLists returns the daemon's current allow/deny lists. Closes
// #99 part 1: enables the attach-mode TUI's URLs pane to render the
// remote daemon's lists. Returns an empty object when no provider
// is wired (control plane reachable but lists not exposed).
func (s *Server) listLists(w http.ResponseWriter, r *http.Request) {
	if s.lists == nil {
		writeJSON(w, map[string][]string{"allow": {}, "deny": {}})
		return
	}
	writeJSON(w, map[string][]string{
		"allow": s.lists.AllowPatterns(),
		"deny":  s.lists.DenyPatterns(),
	})
}

// listLLMDigests returns the advisor's recent classification ring.
// Closes #99 part 2: enables the attach-mode TUI's LLM panel to
// render. Returns an empty array when no advisor is configured.
func (s *Server) listLLMDigests(w http.ResponseWriter, r *http.Request) {
	if s.digests == nil {
		writeJSON(w, []advisor.Digest{})
		return
	}
	writeJSON(w, s.digests.Digests())
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.sessions.Snapshot())
}

func (s *Server) rulesInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"rule_set_version": s.engine.RuleSetVersion(),
		"rules":            s.engine.Rules(),
	})
}

func (s *Server) rulesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.engine.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "reloaded", "rule_set_version": s.engine.RuleSetVersion()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
