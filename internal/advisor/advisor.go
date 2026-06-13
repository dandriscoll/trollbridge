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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
//
// Input carries no record of prior advisor or LLM verdicts. Per
// docs/alignment-principles.md §5, the advisor classifies from
// human input (the lists), the request shape, and the operator's
// directives only — never from what an LLM decided before. There
// is deliberately no field through which a prior verdict could be
// fed in.
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

// Output is the structured response shape the advisor MUST return.
// Per docs/alignment-principles.md §1, this shape does NOT include
// any list-mutation field — the LLM has no opportunity to suggest
// changes to the operator's allow/deny lists. Mutation is human-only.
type Output struct {
	Effect     string   `json:"effect"`
	Scope      string   `json:"scope"`
	Reason     string   `json:"reason"`
	Modifiers  []string `json:"modifiers"`
	Confidence string   `json:"confidence"`
	AdvisorID  string   `json:"advisor_id,omitempty"`
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

	// ModelIdentifier names the upstream model or AOAI deployment
	// the advisor talks to. Surfaced as the `model` attribute on
	// `advisor_consulted` / `advisor_classified` log lines so an
	// operator running multiple deployments (or multiple advisor
	// configs across reloads) can attribute each entry (#157). For
	// AOAI this is the deployment-name parsed from the endpoint
	// URL; for Anthropic / other providers it is `llm.Model`.
	// Empty string omits the attribute.
	ModelIdentifier string
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
	// stats are process-lifetime advisor counters (#137), surfaced via
	// the control plane. Always non-nil after New.
	stats *Stats
}

// Stats returns the live advisor counter set (#137); never nil after New.
func (s *Service) Stats() *Stats { return s.stats }

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
		// #195: default raised from "medium" to "high". Per the
		// issue's framing, only HIGH-confidence verdicts should
		// auto-resolve a hold without operator review; MEDIUM and
		// LOW fall back to ask_user. Operators set
		// `llm.confidence_floor: medium` to opt back into the
		// prior behavior.
		cfg.ConfidenceFloor = "high"
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
	svc := &Service{
		cfg:     cfg,
		prov:    prov,
		cache:   newCache(cfg.CacheTTL),
		digests: NewDigestRing(DigestDefaultCap),
		stats:   &Stats{},
	}
	if n, ok := parseInjectDigestsEnv(); ok && n > 0 {
		injectSyntheticDigests(svc.digests, n)
	}
	return svc
}

// parseInjectDigestsEnv reads TROLLBRIDGE_TEST_INJECT_DIGESTS and
// returns (N, true) when the value is a positive integer. Returns
// (0, false) for absence, empty, non-integer, or non-positive.
// Test-only hook for #160's subprocess pty test — mirrors the
// TROLLBRIDGE_TEST_FAIL_STAGE pattern used in cmd/trollbridge/run.go.
// Silent on parse failure to match that pattern's cautious shape.
func parseInjectDigestsEnv() (int, bool) {
	v := strings.TrimSpace(os.Getenv("TROLLBRIDGE_TEST_INJECT_DIGESTS"))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// injectSyntheticDigests pre-fills the ring with n deterministic
// digests, oldest-first insertion order so r.items[len-1] is the
// newest (matches the production add path). Hosts are
// `synth-host-001.example` … `synth-host-NNN.example`; RequestIDs
// are `synth-req-001` …; Timestamps step by 1 second so newest-
// first ordering survives sorts. Effect=allow, Confidence=high,
// Outcome=classified — picked to render unambiguously in the TUI's
// row format (`HH:MM:SS  <effect>  <confidence>  <host>  — <reason>`).
// Reason names the synthetic origin so a TUI screenshot during
// development is obvious.
//
// Pure test fixture support; never invoked outside parseInjectDigestsEnv's
// positive-N branch.
func injectSyntheticDigests(r *DigestRing, n int) {
	base := time.Now().Add(-time.Duration(n) * time.Second)
	for i := 1; i <= n; i++ {
		r.Add(Digest{
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			RequestID:  fmt.Sprintf("synth-req-%03d", i),
			Method:     "GET",
			Scheme:     "https",
			Host:       fmt.Sprintf("synth-host-%03d.example", i),
			Port:       443,
			Path:       "/",
			Effect:     "allow",
			Confidence: "high",
			AdvisorID:  "synthetic-injection",
			Reason:     "synthetic digest injected via TROLLBRIDGE_TEST_INJECT_DIGESTS",
			Outcome:    DigestOutcomeClassified,
		})
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
	// LLM input hash is set on the request by the server before
	// calling Classify (see #137 side item). The header carries
	// the same value the audit entry records, so audit↔digest
	// correlation is one grep away.
	inputHash := ""
	if req.Headers != nil {
		inputHash = req.Headers.Get("X-Trollbridge-LLM-Input-Hash")
	}
	s.digests.Add(Digest{
		Timestamp:    time.Now().UTC(),
		RequestID:    req.ID,
		Method:       req.Method,
		Scheme:       req.Scheme,
		Host:         req.Host,
		Port:         req.Port,
		Path:         req.Path,
		Effect:       effect,
		Confidence:   confidence,
		AdvisorID:    advisorID,
		Reason:       reason,
		Outcome:      outcome,
		LLMInputHash: inputHash,
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
//
// Classify takes no record of prior advisor/LLM verdicts: there is
// no parameter through which a prior judgment could influence this
// one (docs/alignment-principles.md §5).
func (s *Service) Classify(ctx context.Context, req *types.RequestEvent, ruleSetVersion string, headersRedacted map[string]string, lists *ListContext) (types.Decision, string) {
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
		RuleSetVersion:  ruleSetVersion,
		Directives:      s.cfg.Directives,
		Mode:            s.cfg.Mode,
	}
	if lists != nil {
		in.AllowList = capList(lists.Allow, 200)
		in.DenyList = capList(lists.Deny, 200)
	}

	if s.opLog != nil {
		args := []any{
			"event", oplog.EventAdvisorConsulted,
			"request_id", req.ID,
			"identity", req.IdentityID,
			"method", req.Method,
			"scheme", req.Scheme,
			"host", req.Host,
			"port", req.Port,
		}
		if s.cfg.ModelIdentifier != "" {
			args = append(args, "model", s.cfg.ModelIdentifier)
		}
		s.opLog.Info("advisor consulted", args...)
	}
	s.stats.Consulted.Add(1)
	cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	classifyStart := time.Now()
	out, err := s.prov.Classify(cctx, in)
	classifyLatency := time.Since(classifyStart)
	if err != nil {
		s.stats.Fallback.Add(1)
		s.logFailure(err, req)
		d := s.unavailableDecision("advisor unavailable: " + err.Error())
		s.recordDigest(req, DigestOutcomeUnavailable, string(d.Effect), "", "", d.Reason)
		return d, ""
	}
	// Latency reflects the provider round-trip; record it for every
	// non-error response, before the verdict is sorted into
	// classified vs fallback (#137).
	s.stats.recordLatency(classifyLatency.Milliseconds())

	d, advisorID, verr := s.validate(out, in)
	if verr != nil {
		s.stats.Fallback.Add(1)
		reason := "advisor validation failed: " + verr.Error()
		s.recordDigest(req, DigestOutcomeValidationFailed, string(types.EffectAskUser), "", "", reason)
		return types.Decision{
			Effect: types.EffectAskUser,
			Source: types.SourceLLMAdvisor,
			Reason: reason,
		}, ""
	}
	// An actionable allow/deny is a classification; anything that
	// lands on ask_user (low confidence, advisory-only effect) is a
	// fallback even though the provider responded cleanly (#137).
	if d.Effect == types.EffectAllow || d.Effect == types.EffectDeny {
		s.stats.Classified.Add(1)
	} else {
		s.stats.Fallback.Add(1)
	}
	if s.opLog != nil {
		args := []any{
			"event", oplog.EventAdvisorClassified,
			"request_id", req.ID,
			"host", req.Host,
			"effect", string(d.Effect),
			"confidence", string(out.Confidence),
			"scope", out.Scope,
			"advisor_id", advisorID,
			"reason", out.Reason,
			// #137 side item: latency_ms surfaces the classify
			// round-trip duration so an operator triaging slow
			// classifications doesn't need to subtract timestamps.
			"latency_ms", classifyLatency.Milliseconds(),
		}
		if s.cfg.ModelIdentifier != "" {
			args = append(args, "model", s.cfg.ModelIdentifier)
		}
		s.opLog.Info("advisor classified", args...)
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
	if err == nil {
		return
	}
	event := oplog.EventAdvisorUnknownFail
	switch {
	case errors.Is(err, ErrAdvisorWire):
		event = oplog.EventAdvisorWireFail
		s.stats.ErrWire.Add(1)
	case errors.Is(err, ErrAdvisorSchema):
		event = oplog.EventAdvisorSchemaFail
		s.stats.ErrSchema.Add(1)
	default:
		s.stats.ErrUnknown.Add(1)
	}
	if s.opLog == nil {
		return
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
	// Calls counts Classify invocations. Atomic because Classify runs
	// on the server's advisor goroutine (spawned by holdAndWait) while
	// tests read the count from the test goroutine — a non-atomic int
	// here is a genuine data race under -race (#208).
	Calls atomic.Int64
}

// Classify implements Provider.
func (m *MockProvider) Classify(ctx context.Context, in Input) (Output, error) {
	m.Calls.Add(1)
	if m.Err != nil {
		return Output{}, m.Err
	}
	return m.Output, nil
}
