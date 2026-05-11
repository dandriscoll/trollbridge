// Package advisor wraps the LLM advisor described in DESIGN.md §9.
// The advisor is a CLASSIFIER. It is never authoritative. The
// engine remains the single source of decisional authority.
package advisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/types"
)

// Input is the structured payload sent to the advisor. The fields
// here mirror DESIGN.md §9.3.
//
// AllowList and DenyList are read-only context: the advisor sees
// what the operator already trusts/blocks but cannot modify these
// lists. List mutation is human-only (console input or manual
// file edit).
type Input struct {
	Method          string            `json:"method"`
	Scheme          string            `json:"scheme"`
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Path            string            `json:"path"`
	HeadersRedacted map[string]string `json:"headers_redacted"`
	BodySummary     map[string]any    `json:"body_summary,omitempty"`
	Identity        string            `json:"identity"`
	Tool            string            `json:"tool,omitempty"`
	RecentHistory   []RecentDecision  `json:"recent_history,omitempty"`
	RuleSetVersion  string            `json:"rule_set_version"`
	AllowList       []string          `json:"allow_list,omitempty"`
	DenyList        []string          `json:"deny_list,omitempty"`

	// Directives is the operator-supplied system-prompt content
	// (cfg.LLM.Directives). It is verbatim — trollbridge does not
	// edit it. The advisor endpoint composes it with the rest of
	// the request payload before sending to the LLM.
	Directives string `json:"directives,omitempty"`

	// Mode is the advisor's operating shape (closes #54). Empty
	// defaults to ModeReview. Translators inspect this to decide
	// whether to enable research-mode tools (e.g., web_search).
	Mode string `json:"mode,omitempty"`
}

// RecentDecision is a compact record of a prior decision used as
// advisor context. No bodies, no headers.
type RecentDecision struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Effect string `json:"effect"`
}

// Output is the structured response shape the advisor MUST return.
type Output struct {
	Effect          string   `json:"effect"`
	Scope           string   `json:"scope"`
	Reason          string   `json:"reason"`
	Modifiers       []string `json:"modifiers"`
	SuggestedRule   any      `json:"suggested_rule"`
	Confidence      string   `json:"confidence"`
	AdvisorID       string   `json:"advisor_id,omitempty"`
}

// Provider is the abstract LLM advisor interface. Mock and
// real-provider implementations both satisfy it.
type Provider interface {
	Classify(ctx context.Context, in Input) (Output, error)
}

// Config holds the advisor-side validation policy.
type Config struct {
	Enabled         bool
	ConfidenceFloor string // "low" | "medium" | "high"
	OnUnavailable   string // "ask_user" | "deny" | "allow"
	CacheTTL        time.Duration
	Timeout         time.Duration
	KnownModifiers  map[string]bool

	// Directives is included verbatim in every Input.Directives
	// field sent to the provider. Pulled from cfg.LLM.Directives.
	Directives string

	// Mode is the advisor's operating shape (closes #54). Pulled
	// from cfg.LLM.Mode (with AOAI research-mode fallback applied
	// at server bootstrap). Defaults to ModeReview when empty.
	Mode string
}

// Service is the concrete component the server consults. It owns
// the cache, the validator, and the provider wrapper.
type Service struct {
	cfg   Config
	prov  Provider
	cache *cache
	// opLog, when set, receives layer-tagged Warn entries when the
	// provider returns ErrAdvisorWire / ErrAdvisorSchema (issue #25).
	// nil-safe; tests pass nil.
	opLog Logger
	// digests captures every Classify call's outcome for the TUI's
	// LLM-browse surface (closes #65). Bounded ring; the audit log
	// is the durable record.
	digests *DigestRing
}

// Logger is a tiny subset of *slog.Logger used by the advisor for
// lifecycle (Info), wire-detail (Debug), and failure (Warn) events.
// *slog.Logger satisfies it. Defined here so the advisor package
// does not import log/slog directly through every call site.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// SetLogger wires an optional logger that the service uses to
// emit layer-tagged advisor-failure events.
func (s *Service) SetLogger(l Logger) { s.opLog = l }

// New constructs a Service. prov may be nil; if so, the service is
// disabled and Classify always returns ErrDisabled.
func New(cfg Config, prov Provider) *Service {
	if cfg.ConfidenceFloor == "" {
		cfg.ConfidenceFloor = "medium"
	}
	if cfg.OnUnavailable == "" {
		cfg.OnUnavailable = "ask_user"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.KnownModifiers == nil {
		cfg.KnownModifiers = map[string]bool{}
	}
	return &Service{
		cfg:     cfg,
		prov:    prov,
		cache:   newCache(cfg.CacheTTL),
		digests: NewDigestRing(DigestDefaultCap),
	}
}

// Digests returns the in-memory ring of recent Classify outcomes.
// Used by the operator UI to browse LLM evaluations (closes #65).
func (s *Service) Digests() *DigestRing { return s.digests }

// recordDigest appends one entry to the digest ring. Safe to call
// with a nil receiver (mock services in tests).
func (s *Service) recordDigest(req *types.RequestEvent, outcome, effect, confidence, advisorID, reason string) {
	if s == nil || s.digests == nil || req == nil {
		return
	}
	s.digests.Add(Digest{
		Timestamp:  time.Now().UTC(),
		RequestID:  req.ID,
		Method:     req.Method,
		Scheme:     req.Scheme,
		Host:       req.Host,
		Port:       req.Port,
		Path:       req.Path,
		Effect:     effect,
		Confidence: confidence,
		AdvisorID:  advisorID,
		Reason:     reason,
		Outcome:    outcome,
	})
}

// ErrDisabled means the advisor is not configured.
var ErrDisabled = errors.New("advisor disabled")

// ListContext bundles the operator's flat allow/deny lists for
// inclusion in advisor input. The advisor receives them as
// read-only context.
type ListContext struct {
	Allow []string
	Deny  []string
}

// Classify runs the advisor (with caching), validates the result,
// and returns either a Decision the engine should apply, or a
// fallback decision when the advisor is unavailable / output
// invalid.
//
// The returned Decision is NEVER an elevation: the caller (engine)
// knows the rule said "ask_llm" so any of {allow, deny, ask_user}
// the advisor returns is acceptable; rules saying "ask_user"
// don't reach this code at all.
//
// `lists` MAY be nil. When provided, the entries are included in
// the advisor's Input as read-only context. The advisor MUST NOT
// mutate either list — and the Service offers no API path that
// would let it.
func (s *Service) Classify(ctx context.Context, req *types.RequestEvent, ruleSetVersion string, recent []RecentDecision, headersRedacted map[string]string, lists *ListContext) (types.Decision, string) {
	if !s.cfg.Enabled || s.prov == nil {
		d := s.unavailableDecision("advisor disabled")
		s.recordDigest(req, DigestOutcomeUnavailable, string(d.Effect), "", "", d.Reason)
		return d, ""
	}
	cacheKey := buildCacheKey(ruleSetVersion, req)
	if cached, ok := s.cache.get(cacheKey); ok {
		return cached.decision, cached.advisorID
	}

	in := Input{
		Method:          req.Method,
		Scheme:          req.Scheme,
		Host:            req.Host,
		Port:            req.Port,
		Path:            req.Path,
		HeadersRedacted: headersRedacted,
		Identity:        req.IdentityID,
		RecentHistory:   recent,
		RuleSetVersion:  ruleSetVersion,
		Directives:      s.cfg.Directives,
		Mode:            s.cfg.Mode,
	}
	if lists != nil {
		in.AllowList = capList(lists.Allow, 200)
		in.DenyList = capList(lists.Deny, 200)
	}

	if s.opLog != nil {
		s.opLog.Info("advisor consulted",
			"event", oplog.EventAdvisorConsulted,
			"request_id", req.ID,
			"identity", req.IdentityID,
			"method", req.Method,
			"scheme", req.Scheme,
			"host", req.Host,
			"port", req.Port)
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	out, err := s.prov.Classify(cctx, in)
	if err != nil {
		s.logFailure(err, req)
		d := s.unavailableDecision("advisor unavailable: " + err.Error())
		s.recordDigest(req, DigestOutcomeUnavailable, string(d.Effect), "", "", d.Reason)
		return d, ""
	}

	d, advisorID, verr := s.validate(out, in)
	if verr != nil {
		reason := "advisor validation failed: " + verr.Error()
		s.recordDigest(req, DigestOutcomeValidationFailed, string(types.EffectAskUser), "", "", reason)
		return types.Decision{
			Effect: types.EffectAskUser,
			Source: types.SourceLLMAdvisor,
			Reason: reason,
		}, ""
	}
	if s.opLog != nil {
		s.opLog.Info("advisor classified",
			"event", oplog.EventAdvisorClassified,
			"request_id", req.ID,
			"host", req.Host,
			"effect", string(d.Effect),
			"confidence", string(out.Confidence),
			"scope", out.Scope,
			"advisor_id", advisorID,
			"reason", out.Reason)
	}
	s.recordDigest(req, DigestOutcomeClassified, string(d.Effect), string(out.Confidence), advisorID, out.Reason)
	s.cache.put(cacheKey, cacheValue{decision: d, advisorID: advisorID})
	return d, advisorID
}

// logFailure emits a layer-tagged Warn for an advisor provider
// failure (issue #25). Wire failures (HTTP transport, timeout)
// and schema failures (200 with malformed body) used to read the
// same in the operational log; this distinguishes them so an
// operator debugging an advisor outage doesn't have to run
// `trollbridge doctor` to learn the layer.
func (s *Service) logFailure(err error, req *types.RequestEvent) {
	if s.opLog == nil || err == nil {
		return
	}
	event := oplog.EventAdvisorUnknownFail
	switch {
	case errors.Is(err, ErrAdvisorWire):
		event = oplog.EventAdvisorWireFail
	case errors.Is(err, ErrAdvisorSchema):
		event = oplog.EventAdvisorSchemaFail
	}
	s.opLog.Warn("advisor classify failed",
		"event", event,
		"request_id", req.ID,
		"host", req.Host,
		"error", err.Error())
}

func (s *Service) unavailableDecision(reason string) types.Decision {
	switch s.cfg.OnUnavailable {
	case "allow":
		return types.Decision{Effect: types.EffectAllow, Source: types.SourceLLMAdvisor, Reason: reason + "; on_unavailable=allow"}
	case "deny":
		return types.Decision{Effect: types.EffectDeny, Source: types.SourceLLMAdvisor, Reason: reason + "; on_unavailable=deny"}
	default:
		return types.Decision{Effect: types.EffectAskUser, Source: types.SourceLLMAdvisor, Reason: reason + "; on_unavailable=ask_user"}
	}
}

// validate enforces the advisor schema, modifier whitelist, and
// confidence floor. Never elevates.
func (s *Service) validate(out Output, in Input) (types.Decision, string, error) {
	out.Effect = strings.TrimSpace(strings.ToLower(out.Effect))
	out.Confidence = strings.TrimSpace(strings.ToLower(out.Confidence))
	out.Scope = strings.TrimSpace(strings.ToLower(out.Scope))

	switch out.Effect {
	case "allow", "deny", "ask_user", "narrow_scope", "redact_and_retry", "prefer_structured_tool":
	default:
		return types.Decision{}, "", fmt.Errorf("unknown effect %q", out.Effect)
	}
	switch out.Confidence {
	case "low", "medium", "high":
	default:
		return types.Decision{}, "", fmt.Errorf("unknown confidence %q", out.Confidence)
	}

	// Confidence floor: if the advisor is below the floor, fall
	// back to ask_user.
	if !confidenceMeetsFloor(out.Confidence, s.cfg.ConfidenceFloor) {
		return types.Decision{
			Effect: types.EffectAskUser,
			Source: types.SourceLLMAdvisor,
			Reason: fmt.Sprintf("advisor confidence %s below floor %s; falling back to ask_user", out.Confidence, s.cfg.ConfidenceFloor),
		}, out.AdvisorID, nil
	}

	// Modifier whitelist.
	mods := []string{}
	for _, m := range out.Modifiers {
		if s.cfg.KnownModifiers[m] {
			mods = append(mods, m)
		}
	}

	// Map advisor effect → engine Effect. Some advisor effects
	// reduce to ask_user pending Phase 5 features.
	effect := types.EffectAskUser
	switch out.Effect {
	case "allow":
		effect = types.EffectAllow
	case "deny":
		effect = types.EffectDeny
	case "ask_user":
		effect = types.EffectAskUser
	default:
		// narrow_scope / redact_and_retry / prefer_structured_tool
		// are advisory hints in this phase; we route to ask_user
		// so the operator sees the advisor's recommendation.
		effect = types.EffectAskUser
	}

	advisorID := out.AdvisorID
	if advisorID == "" {
		advisorID = "advisor-" + hashString(out.Reason+out.Confidence)[:12]
	}

	return types.Decision{
		Effect:    effect,
		Source:    types.SourceLLMAdvisor,
		AdvisorID: advisorID,
		Reason:    out.Reason,
		Scope:     out.Scope,
		Modifiers: mods,
	}, advisorID, nil
}

func confidenceMeetsFloor(c, floor string) bool {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2}
	return rank[c] >= rank[floor]
}

// hashString returns a hex sha256.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// buildCacheKey hashes the request shape into a stable key.
func buildCacheKey(ruleSetVersion string, req *types.RequestEvent) string {
	parts := []string{
		ruleSetVersion,
		req.IdentityID,
		req.Method,
		req.Scheme,
		req.Host,
		fmt.Sprintf("%d", req.Port),
		req.Path,
	}
	return hashString(strings.Join(parts, "|"))
}

// CanonicalizeInput returns a stable JSON serialization of the
// advisor input (used for the audit log's llm_input_hash).
func CanonicalizeInput(in Input) string {
	buf, _ := json.Marshal(in)
	return hashString(string(buf))
}

// capList returns the first n entries of `entries` (or all of them
// if shorter) so the LLM input doesn't blow up on huge lists.
func capList(entries []string, n int) []string {
	if len(entries) <= n {
		out := make([]string, len(entries))
		copy(out, entries)
		return out
	}
	out := make([]string, n)
	copy(out, entries[:n])
	return out
}

type cacheValue struct {
	decision  types.Decision
	advisorID string
	expiresAt time.Time
}

type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheValue
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, m: map[string]cacheValue{}}
}

func (c *cache) get(k string) (cacheValue, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	if !ok || time.Now().After(v.expiresAt) {
		delete(c.m, k)
		return cacheValue{}, false
	}
	return v, true
}

func (c *cache) put(k string, v cacheValue) {
	v.expiresAt = time.Now().Add(c.ttl)
	c.mu.Lock()
	c.m[k] = v
	c.mu.Unlock()
}

// HTTPClassifier is a Provider that translates the trollbridge
// advisor Input into a provider-specific native API request (per
// the configured Translator), POSTs it, and parses the response
// back into the trollbridge Output.
//
// Construct via NewHTTPClassifier. The Translator is mandatory; nil
// translator with non-empty endpoint is a configuration error
// surfaced at first Classify.
type HTTPClassifier struct {
	Endpoint   string
	APIKey     string
	Model      string
	Translator Translator
	Client     *http.Client
	// OpLog, when set, receives a Debug `event=advisor_wire_response`
	// record per Classify call carrying method, url, status, and a
	// truncated body sample — so an operator running with
	// --log-level=debug can diagnose 4xx/5xx wire failures without
	// re-running `trollbridge doctor` and without parsing the
	// returned err.Error() blob. Closes #36 wire-detail closure.
	OpLog Logger
}

// Classify implements Provider. Translator builds the wire body
// and headers; HTTPClassifier owns transport — POST, status
// capture, body read, error wrapping with ErrAdvisorWire /
// ErrAdvisorSchema for the caller to distinguish.
func (h *HTTPClassifier) Classify(ctx context.Context, in Input) (Output, error) {
	if h.Translator == nil {
		return Output{}, fmt.Errorf("advisor: HTTPClassifier has no Translator configured")
	}
	if h.Client == nil {
		h.Client = &http.Client{Timeout: 8 * time.Second}
	}
	body, headers, err := h.Translator.BuildRequest(in, h.Model, h.APIKey)
	if err != nil {
		return Output{}, fmt.Errorf("advisor: build request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", h.Endpoint, strings.NewReader(string(body)))
	if err != nil {
		return Output{}, fmt.Errorf("advisor: new request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	dialStart := time.Now()
	resp, err := h.Client.Do(req)
	dialMS := time.Since(dialStart).Milliseconds()
	if err != nil {
		if h.OpLog != nil {
			h.OpLog.Debug("advisor wire transport error",
				"event", oplog.EventAdvisorWireResponse,
				"method", "POST",
				"url", h.Endpoint,
				"duration_ms", dialMS,
				"error", err.Error())
		}
		return Output{}, fmt.Errorf("%w: %v", ErrAdvisorWire, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if h.OpLog != nil {
			h.OpLog.Debug("advisor wire response body read error",
				"event", oplog.EventAdvisorWireResponse,
				"method", "POST",
				"url", h.Endpoint,
				"status", resp.StatusCode,
				"duration_ms", dialMS,
				"error", err.Error())
		}
		return Output{}, fmt.Errorf("%w: read response: %v", ErrAdvisorWire, err)
	}
	if h.OpLog != nil {
		args := []any{
			"event", oplog.EventAdvisorWireResponse,
			"method", "POST",
			"url", h.Endpoint,
			"status", resp.StatusCode,
			"duration_ms", dialMS,
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			args = append(args, "body_sample", truncateForLog(string(respBody), 256))
		}
		h.OpLog.Debug("advisor wire response", args...)
	}
	return h.Translator.ParseResponse(resp.StatusCode, respBody)
}

// MockProvider supports tests; returns a fixed Output or error.
type MockProvider struct {
	Output Output
	Err    error
	Calls  int
}

// Classify implements Provider.
func (m *MockProvider) Classify(ctx context.Context, in Input) (Output, error) {
	m.Calls++
	if m.Err != nil {
		return Output{}, m.Err
	}
	return m.Output, nil
}
