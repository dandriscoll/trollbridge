package types

import (
	"net/http"
	"time"
)

// RequestEvent is the normalized representation of an inbound proxy
// request used for policy decisions and audit logging. See
// DESIGN.md §4.1.
type RequestEvent struct {
	ID         string
	SessionID  string
	IdentityID string
	Timestamp  time.Time

	Method  string // "CONNECT" / "GET" / "POST" / ...
	Scheme  string // "http" / "https-tunneled" / "https-intercepted"
	Host    string
	Port    int
	Path    string // "" if CONNECT and not intercepted
	Headers http.Header

	ClientAddr string

	BodyAvailable bool
	BodySize      int64
	BodySample    []byte // up to MaxBodySample bytes; redacted
}

// Effect is the outcome of a policy Decision.
type Effect string

const (
	EffectAllow                  Effect = "allow"
	EffectDeny                   Effect = "deny"
	EffectAskUser                Effect = "ask_user"
	EffectAskLLM                 Effect = "ask_llm"
	EffectAskUserResolvedAllow   Effect = "ask_user_resolved_allow"
	EffectAskUserResolvedDeny    Effect = "ask_user_resolved_deny"
	EffectAskUserTimedOut        Effect = "ask_user_timed_out"
	// EffectAskUserSignaled fires when approvals.signal_after_seconds
	// elapses with the hold still pending. The proxy emits a 471
	// pending response to the consumer (with the hold id) and closes
	// the connection — the hold itself remains in the queue for
	// operator resolution and audit. Consumers see a fast in-band
	// signal instead of hanging until approvals.timeout_seconds.
	// Closes #43 (round 6 of the ask-case-silent-hang class).
	EffectAskUserSignaled Effect = "ask_user_signaled"
)

// DecisionSource records which subsystem produced a decision.
type DecisionSource string

const (
	SourceRule            DecisionSource = "rule"
	SourceDefault         DecisionSource = "default"
	SourceLLMAdvisor      DecisionSource = "llm_advisor"
	SourceApprovalQueue   DecisionSource = "approval_queue"
	SourceApprovalTimeout DecisionSource = "approval_timeout"
	SourceAllowList       DecisionSource = "allowlist"
	SourceDenyList        DecisionSource = "denylist"
)

// Decision is the policy engine's output for a RequestEvent.
type Decision struct {
	Effect    Effect
	Source    DecisionSource
	RuleID    string
	AdvisorID string
	Reason    string
	Scope     string   // "once" | "session" | "rule"
	Modifiers []string // names of transformations to apply
	Expires   time.Time
	// HoldID is set on EffectAskUserSignaled decisions so the
	// response-writer path can surface it as an X-Trollbridge-Hold-Id
	// header. Empty for non-signaled decisions.
	HoldID string
}
