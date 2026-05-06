// Package control implements drawbridge's HTTP control plane (the
// approval API). It lives on a SEPARATE listener from the proxy
// listener — DESIGN.md §13.4 `approvals.control_listen`.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dandriscoll/drawbridge/internal/approvals"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/sessions"
)

// CAOps is the subset of the CA package the control plane needs.
type CAOps interface {
	FlushCache()
	SHA256Fingerprint() string
}

// Server is the control-plane HTTP listener.
type Server struct {
	addr     string
	queue    *approvals.Queue
	sessions *sessions.Tracker
	engine   *policy.Engine
	ca       CAOps
	srv      *http.Server
}

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

// ListenAndServe starts the control plane on addr; returns the
// concrete bound address (helpful when addr=":0").
func (s *Server) ListenAndServe(ctx context.Context) (string, error) {
	if s.addr == "" {
		return "", nil
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/holds", s.listHolds)
	mux.HandleFunc("/v1/holds/", s.holdAction) // /v1/holds/<id>/approve|deny
	mux.HandleFunc("/v1/sessions", s.listSessions)
	mux.HandleFunc("/v1/rules", s.rulesInfo)
	mux.HandleFunc("/v1/rules/reload", s.rulesReload)
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/v1/ca/flush-cache", func(w http.ResponseWriter, r *http.Request) {
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
	})
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
			fmt.Println("drawbridge: control plane error:", err)
		}
	}()
	return ln.Addr().String(), nil
}

func (s *Server) listHolds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.queue.Pending())
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
		if !s.queue.Approve(id, body.Scope) {
			http.Error(w, "hold not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "approved", "id": id, "scope": body.Scope})
	case "deny":
		if !s.queue.Deny(id, body.Reason) {
			http.Error(w, "hold not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "denied", "id": id})
	default:
		http.Error(w, "unknown action; expected approve|deny", http.StatusBadRequest)
	}
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
