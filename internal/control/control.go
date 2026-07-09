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
	"io"
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
	"github.com/dandriscoll/trollbridge/internal/reloadstatus"
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

// ListWriter performs operator-driven list mutations on the
// daemon's persisted trollbridge.yaml. Used by the attach-mode
// list-edit endpoints (#189) so a consumer-host operator can
// approve / deny URLs without SSHing to the proxy. The concrete
// implementer (in cmd/trollbridge/run.go) routes through the
// configwrite.OperatorApprove / OperatorDeny primitives so the
// reload-after-write invariant matches the in-process operator
// path (#194).
type ListWriter interface {
	// AddAllow / AddDeny consolidate (remove from opposite list)
	// then add to the named list. Idempotent on the named-list
	// side; returns true when at least one of the two operations
	// mutated the YAML.
	AddAllow(pattern string) (bool, error)
	AddDeny(pattern string) (bool, error)
	// RemoveAllow / RemoveDeny strip the pattern from the named
	// list. Idempotent: no-op when the pattern is absent.
	RemoveAllow(pattern string) (bool, error)
	RemoveDeny(pattern string) (bool, error)
}

// DigestsProvider exposes the advisor's digest ring to the control
// plane. Closes #99 part 2 (attach-mode TUI parity for the LLM
// panel). Returns nil when no advisor is configured.
type DigestsProvider interface {
	Digests() []advisor.Digest
}

// AdvisorMetricsProvider exposes the advisor's process-lifetime
// counters on /v1/advisor/metrics (#137). Returns nil when no advisor
// is configured. The concrete provider is *advisor.Service.
type AdvisorMetricsProvider interface {
	Stats() *advisor.Stats
}

// ReloadStatusProvider surfaces the daemon's most-recent hot-reload
// outcome on /v1/rules so the TUI badge (#129) can render it. The
// concrete provider lives on *server.Server; control takes an
// interface to avoid an import cycle.
type ReloadStatusProvider interface {
	ReloadStatus() reloadstatus.Status
}

// SuggestionProvider exposes the quiet-moment generalization
// suggestion lifecycle on /v1/suggestion (closes #168). The
// concrete provider lives in internal/suggestion; control takes an
// interface to avoid an import cycle.
type SuggestionProvider interface {
	Active() *SuggestionRow
	Accept(ctx context.Context, id string) error
	Decline(ctx context.Context, id string) error
	// Skip defers the active suggestion (#214): no decision is
	// persisted (no decline row, unlike Decline) and the next
	// recommendation is offered instead.
	Skip(ctx context.Context, id string) error
	// SuggestNow runs the detector on demand, bypassing the quiet
	// gate (#174), so the operator can request a scan instead of
	// waiting for an idle moment.
	SuggestNow(ctx context.Context)
}

// SuggestionRow is the wire-shape returned by GET /v1/suggestion.
// suggestion.Manager satisfies SuggestionProvider by translating
// its internal Suggestion type into this struct.
type SuggestionRow struct {
	SuggestionID     string   `json:"suggestion_id"`
	Axis             string   `json:"axis"`
	List             string   `json:"list"`
	SourceEntries    []string `json:"source_entries"`
	SuggestedPattern string   `json:"suggested_pattern"`
	Reason           string   `json:"reason"`
	AxesRemaining    int      `json:"axes_remaining"`
	OfferedAt        string   `json:"offered_at"`

	// Pattern-shaped suggestion fields (#203 follow-up). Populated
	// on pattern:* axes; omitted otherwise so attach-mode clients
	// that don't know about patterns still parse the row.
	PatternName       string            `json:"pattern_name,omitempty"`
	PatternComponents map[string]string `json:"pattern_components,omitempty"`
	PatternMethod     string            `json:"pattern_method,omitempty"`
}

// Server is the control-plane HTTPS listener.
type Server struct {
	addr         string
	queue        *approvals.Queue
	sessions     *sessions.Tracker
	engine       *policy.Engine
	ops          *opstream.Ring
	lists        ListsProvider
	listWriter   ListWriter
	digests      DigestsProvider
	advisorStats AdvisorMetricsProvider
	reloadStatus ReloadStatusProvider
	ca           CAOps
	tlsProv      TLSProvider
	srv          *http.Server
	suggestion   SuggestionProvider
	openMode     OpenModeProvider

	opLog *slog.Logger
}

// OpenModeProvider exposes the time-boxed "allow all traffic" window
// (#209) on /v1/open so an attach-mode operator can open/extend/close it.
// *server.Server satisfies this via an adapter.
type OpenModeProvider interface {
	ExtendOpenMode() time.Time
	CloseOpenMode()
	OpenModeState() (active bool, until time.Time)
}

// SetOpenMode wires the open-mode controller so /v1/open can read and
// drive it. When unset, /v1/open returns 404 (the daemon does not expose
// open mode).
func (s *Server) SetOpenMode(p OpenModeProvider) { s.openMode = p }

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

// SetListWriter wires the list-mutation primitive used by the
// attach-mode list-edit endpoints (#189). nil disables the
// mutation endpoints (they return 405 / 503).
func (s *Server) SetListWriter(w ListWriter) { s.listWriter = w }

// SetDigests wires the advisor's digest ring into the control plane
// so /v1/llm-digests can return recent classifications. Closes #99
// part 2.
func (s *Server) SetDigests(p DigestsProvider) { s.digests = p }

// SetAdvisorStats wires the advisor's counter set into the control
// plane so /v1/advisor/metrics can return them (#137).
func (s *Server) SetAdvisorStats(p AdvisorMetricsProvider) { s.advisorStats = p }

// SetReloadStatusProvider wires the daemon's reload-status surface
// so /v1/rules can report the most-recent hot-reload outcome. The
// TUI badge in the approvals pane consumes this (closes #129).
func (s *Server) SetReloadStatusProvider(p ReloadStatusProvider) { s.reloadStatus = p }

// SetTLS wires the TLS-issuing provider used to bring up the mTLS
// listener.
func (s *Server) SetTLS(p TLSProvider) { s.tlsProv = p }

// SetSuggestion wires the quiet-moment suggestion lifecycle so
// /v1/suggestion can return the active row and accept/decline
// arrives at the right manager. nil disables the endpoint surface
// (404). Closes #168.
func (s *Server) SetSuggestion(p SuggestionProvider) { s.suggestion = p }

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
	mux.HandleFunc("/v1/lists/allow", authd(s.listEditAllow))   // #189: POST add, DELETE remove
	mux.HandleFunc("/v1/lists/deny", authd(s.listEditDeny))     // #189: POST add, DELETE remove
	mux.HandleFunc("/v1/llm-digests", authd(s.listLLMDigests))  // closes #99 part 2
	mux.HandleFunc("/v1/advisor/metrics", authd(s.advisorMetrics)) // #137
	mux.HandleFunc("/v1/sessions", authd(s.listSessions))
	mux.HandleFunc("/v1/rules", authd(s.rulesInfo))
	mux.HandleFunc("/v1/rules/reload", authd(s.rulesReload))
	mux.HandleFunc("/v1/suggestion", authd(s.suggestionGet))                  // closes #168
	mux.HandleFunc("/v1/suggestion/accept", authd(s.suggestionAccept))        // closes #168
	mux.HandleFunc("/v1/suggestion/decline", authd(s.suggestionDecline))      // closes #168
	mux.HandleFunc("/v1/suggestion/skip", authd(s.suggestionSkip))            // #214 defer, no decision
	mux.HandleFunc("/v1/suggestion/scan", authd(s.suggestionScan))            // #174 on-demand
	mux.HandleFunc("/v1/open", authd(s.openModeHandler))                      // #209: GET state / POST extend / DELETE close
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

// listEditAllow handles POST/DELETE on /v1/lists/allow for #189
// attach-mode list editing. Body: {"pattern": "..."}.
//   POST   → AddAllow (consolidates: removes from deny first).
//   DELETE → RemoveAllow.
// Returns {"changed": true|false}. 503 when no ListWriter is wired
// (in-process daemon misconfiguration); 405 for unsupported
// methods; 400 for missing pattern.
func (s *Server) listEditAllow(w http.ResponseWriter, r *http.Request) {
	s.listEdit(w, r, "allow")
}

func (s *Server) listEditDeny(w http.ResponseWriter, r *http.Request) {
	s.listEdit(w, r, "deny")
}

func (s *Server) listEdit(w http.ResponseWriter, r *http.Request, list string) {
	if s.listWriter == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "list mutation not available — daemon was not started with the list-edit writer",
		})
		return
	}
	switch r.Method {
	case http.MethodPost, http.MethodDelete:
		// supported
	default:
		w.Header().Set("Allow", "POST, DELETE")
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "use POST to add, DELETE to remove",
		})
		return
	}
	body := struct {
		Pattern string `json:"pattern"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON body: " + err.Error(),
		})
		return
	}
	pattern := strings.TrimSpace(body.Pattern)
	if pattern == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": `pattern is required (JSON body: {"pattern": "..."})`,
		})
		return
	}
	var (
		changed bool
		err     error
	)
	switch r.Method {
	case http.MethodPost:
		switch list {
		case "allow":
			changed, err = s.listWriter.AddAllow(pattern)
		case "deny":
			changed, err = s.listWriter.AddDeny(pattern)
		}
	case http.MethodDelete:
		switch list {
		case "allow":
			changed, err = s.listWriter.RemoveAllow(pattern)
		case "deny":
			changed, err = s.listWriter.RemoveDeny(pattern)
		}
	}
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}
	writeJSON(w, map[string]bool{"changed": changed})
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

// advisorMetrics returns the advisor's process-lifetime counters (#137).
// Empty snapshot when no advisor is configured.
func (s *Server) advisorMetrics(w http.ResponseWriter, r *http.Request) {
	if s.advisorStats == nil {
		writeJSON(w, advisor.StatsSnapshot{})
		return
	}
	writeJSON(w, s.advisorStats.Stats().Snapshot())
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.sessions.Snapshot())
}

func (s *Server) rulesInfo(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{
		"rule_set_version": s.engine.RuleSetVersion(),
		"rules":            s.engine.Rules(),
	}
	if s.reloadStatus != nil {
		// Closes #129: surface the most-recent hot-reload outcome
		// alongside the loaded rule set. JSON tags on
		// reloadstatus.Status omit the fields when LastAt is zero
		// (no reload attempted) or LastError is empty (last
		// attempt succeeded) — backwards-compatible with the
		// pre-#129 response shape.
		st := s.reloadStatus.ReloadStatus()
		if !st.LastAt.IsZero() {
			payload["last_reload_at"] = st.LastAt
			payload["last_reload_source"] = st.LastSource
		}
		if st.LastError != "" {
			payload["last_reload_error"] = st.LastError
		}
	}
	writeJSON(w, payload)
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

// suggestionGet returns the daemon's active suggestion (200) or
// 204 when none. Closes part of #168.
// OpenModeState is the /v1/open response body (#209).
type OpenModeState struct {
	Active bool      `json:"active"`
	Until  time.Time `json:"until"`
}

// openModeHandler serves the time-boxed open window: GET reports state,
// POST opens/extends it, DELETE closes it. All three return the
// resulting state so the caller updates its view in one round trip.
func (s *Server) openModeHandler(w http.ResponseWriter, r *http.Request) {
	if s.openMode == nil {
		http.Error(w, "open mode not configured", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// state below
	case http.MethodPost:
		s.openMode.ExtendOpenMode()
	case http.MethodDelete:
		s.openMode.CloseOpenMode()
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	active, until := s.openMode.OpenModeState()
	writeJSON(w, OpenModeState{Active: active, Until: until})
}

func (s *Server) suggestionGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.suggestion == nil {
		http.Error(w, "suggestion mode not configured", http.StatusNotFound)
		return
	}
	row := s.suggestion.Active()
	if row == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, row)
}

// suggestionAccept resolves the named suggestion by persisting its
// pattern to the allow/deny list. 200 on success, 409 when the id
// is stale, 410 when there is no active suggestion.
func (s *Server) suggestionAccept(w http.ResponseWriter, r *http.Request) {
	id, err := readSuggestionID(w, r)
	if err != nil {
		return
	}
	if s.suggestion == nil {
		http.Error(w, "suggestion mode not configured", http.StatusNotFound)
		return
	}
	if err := s.suggestion.Accept(r.Context(), id); err != nil {
		mapSuggestionErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "accepted", "suggestion_id": id})
}

// suggestionDecline rotates to the next axis OR writes the YAML
// decline row, depending on the manager's session state.
func (s *Server) suggestionDecline(w http.ResponseWriter, r *http.Request) {
	id, err := readSuggestionID(w, r)
	if err != nil {
		return
	}
	if s.suggestion == nil {
		http.Error(w, "suggestion mode not configured", http.StatusNotFound)
		return
	}
	if err := s.suggestion.Decline(r.Context(), id); err != nil {
		mapSuggestionErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "declined", "suggestion_id": id})
}

// suggestionSkip defers the active suggestion (#214) without recording
// a decision: no decline row is written and the recommendation is
// re-offered in a future process. 200 on success, 409 when the id is
// stale, 410 when there is no active suggestion — same mapping as
// accept/decline.
func (s *Server) suggestionSkip(w http.ResponseWriter, r *http.Request) {
	id, err := readSuggestionID(w, r)
	if err != nil {
		return
	}
	if s.suggestion == nil {
		http.Error(w, "suggestion mode not configured", http.StatusNotFound)
		return
	}
	if err := s.suggestion.Skip(r.Context(), id); err != nil {
		mapSuggestionErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "skipped", "suggestion_id": id})
}

// suggestionScan runs an on-demand detector pass (#174) and returns
// the resulting active suggestion (200) or 204 when the scan found
// nothing to offer.
func (s *Server) suggestionScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.suggestion == nil {
		http.Error(w, "suggestion mode not configured", http.StatusNotFound)
		return
	}
	s.suggestion.SuggestNow(r.Context())
	row := s.suggestion.Active()
	if row == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, row)
}

func readSuggestionID(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", errMethod
	}
	var body struct {
		SuggestionID string `json:"suggestion_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return "", err
	}
	if body.SuggestionID == "" {
		http.Error(w, "suggestion_id is required", http.StatusBadRequest)
		return "", errBadID
	}
	return body.SuggestionID, nil
}

var (
	errMethod = errorsNew("method-not-allowed")
	errBadID  = errorsNew("bad-id")
)

func errorsNew(s string) error { return controlErr(s) }

type controlErr string

func (e controlErr) Error() string { return string(e) }

func mapSuggestionErr(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "no active suggestion":
		http.Error(w, err.Error(), http.StatusGone) // 410
	case "suggestion id mismatch":
		http.Error(w, err.Error(), http.StatusConflict) // 409
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeJSONStatus writes the given HTTP status code AND a JSON body
// (#189). Used by the list-edit handlers so the attach client gets
// a structured error to render.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
