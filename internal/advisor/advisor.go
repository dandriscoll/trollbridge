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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/drawbridge/internal/types"
)

// Input is the structured payload sent to the advisor. The fields
// here mirror DESIGN.md §9.3.
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
}

// Service is the concrete component the server consults. It owns
// the cache, the validator, and the provider wrapper.
type Service struct {
	cfg   Config
	prov  Provider
	cache *cache
}

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
	return &Service{cfg: cfg, prov: prov, cache: newCache(cfg.CacheTTL)}
}

// ErrDisabled means the advisor is not configured.
var ErrDisabled = errors.New("advisor disabled")

// Classify runs the advisor (with caching), validates the result,
// and returns either a Decision the engine should apply, or a
// fallback decision when the advisor is unavailable / output
// invalid.
//
// The returned Decision is NEVER an elevation: the caller (engine)
// knows the rule said "ask_llm" so any of {allow, deny, ask_user}
// the advisor returns is acceptable; rules saying "ask_user"
// don't reach this code at all.
func (s *Service) Classify(ctx context.Context, req *types.RequestEvent, ruleSetVersion string, recent []RecentDecision, headersRedacted map[string]string) (types.Decision, string) {
	if !s.cfg.Enabled || s.prov == nil {
		return s.unavailableDecision("advisor disabled"), ""
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
	}

	cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	out, err := s.prov.Classify(cctx, in)
	if err != nil {
		return s.unavailableDecision("advisor unavailable: " + err.Error()), ""
	}

	d, advisorID, err := s.validate(out, in)
	if err != nil {
		return types.Decision{
			Effect: types.EffectAskUser,
			Source: types.SourceLLMAdvisor,
			Reason: "advisor validation failed: " + err.Error(),
		}, ""
	}
	s.cache.put(cacheKey, cacheValue{decision: d, advisorID: advisorID})
	return d, advisorID
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

// HTTPClassifier is a generic JSON-over-HTTP advisor provider that
// posts the Input to a configured endpoint and expects the
// configured response shape. The DESIGN.md §9 schema is the
// expected shape; HTTPClassifier is intentionally generic so
// operators can wire any compatible endpoint.
type HTTPClassifier struct {
	Endpoint string
	APIKey   string
	Headers  map[string]string
	Client   *http.Client
}

// Classify implements Provider.
func (h *HTTPClassifier) Classify(ctx context.Context, in Input) (Output, error) {
	if h.Client == nil {
		h.Client = &http.Client{Timeout: 8 * time.Second}
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, "POST", h.Endpoint, strings.NewReader(string(body)))
	if err != nil {
		return Output{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return Output{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Output{}, fmt.Errorf("advisor http %s", resp.Status)
	}
	var out Output
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Output{}, fmt.Errorf("advisor json decode: %w", err)
	}
	return out, nil
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
