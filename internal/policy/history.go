package policy

import (
	"strings"
	"sync"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// HistoryEntry is one prior-decision record kept in memory for the
// prior_decision match clause.
type HistoryEntry struct {
	When       time.Time
	IdentityID string
	Host       string
	Effect     string
	RuleID     string
}

// History is a fixed-size sliding window of recent decisions.
type History struct {
	mu  sync.Mutex
	buf []HistoryEntry
	cap int
}

// NewHistory returns a History bounded to capacity entries.
func NewHistory(capacity int) *History {
	if capacity <= 0 {
		capacity = 1024
	}
	return &History{cap: capacity, buf: make([]HistoryEntry, 0, capacity)}
}

// Record appends a decision to the history. Oldest entries are
// dropped when the buffer is full.
//
// LLM-sourced decisions are deliberately NOT recorded (#141): the
// prior_decision match clause reads this surface, and matching a
// prior LLM verdict would create a second unaudited LLM-feedback
// path (the advisor decides once, a deterministic rule re-applies
// that decision later without re-consulting). prior_decision is
// scoped to human + static-policy decisions; the digest ring is
// the audit surface for LLM verdicts.
func (h *History) Record(req *types.RequestEvent, d types.Decision, when time.Time) {
	if h == nil {
		return
	}
	if d.Source == types.SourceLLMAdvisor {
		return
	}
	e := HistoryEntry{
		When:       when,
		IdentityID: req.IdentityID,
		Host:       req.Host,
		Effect:     string(d.Effect),
		RuleID:     d.RuleID,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buf) >= h.cap {
		copy(h.buf, h.buf[1:])
		h.buf = h.buf[:h.cap-1]
	}
	h.buf = append(h.buf, e)
}

// HasOppositeEffect reports whether the buffer contains any
// recorded decision on the given host whose effect differs from
// currentEffect. Walks newest to oldest; the whole buffer is in
// scope (no time window — capacity bounds the lookback). Used by
// the TUI to flag decision reversals at row-render time
// (closes #192). Read-only over the existing history surface; no
// state change.
//
// Effect normalization (#192 reopen): operator-resolved decisions
// record with the verbose `Effect = "ask_user_resolved_allow"` /
// `_deny` strings; the TUI passes the abbreviated `"allow"` /
// `"deny"`. Both stored values and currentEffect are normalized
// via trimAskUserResolvedPrefix so the comparison is on the
// effective direction, not the literal string.
func (h *History) HasOppositeEffect(host, currentEffect string) bool {
	if h == nil || host == "" || currentEffect == "" {
		return false
	}
	wantEffect := trimAskUserResolvedPrefix(currentEffect)
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.buf) - 1; i >= 0; i-- {
		e := h.buf[i]
		if e.Host != host {
			continue
		}
		got := trimAskUserResolvedPrefix(e.Effect)
		if got != "" && got != wantEffect {
			return true
		}
	}
	return false
}

// trimAskUserResolvedPrefix maps EffectAskUserResolved{Allow,Deny}
// values to their abbreviated allow/deny equivalent so the
// HasOppositeEffect comparison is on the effective direction
// rather than the literal recorded string.
func trimAskUserResolvedPrefix(effect string) string {
	return strings.TrimPrefix(effect, "ask_user_resolved_")
}

// Match returns true if any entry in the last `within` seconds
// matches the configured criteria.
func (h *History) Match(req *types.RequestEvent, m *PriorDecisionMatch, now time.Time) bool {
	if h == nil || m == nil {
		return false
	}
	cutoff := now.Add(-time.Duration(m.WithinSeconds) * time.Second)
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.buf) - 1; i >= 0; i-- {
		e := h.buf[i]
		if e.When.Before(cutoff) {
			break
		}
		if m.Effect != "" && e.Effect != m.Effect {
			continue
		}
		if m.SameIdentity && e.IdentityID != req.IdentityID {
			continue
		}
		if m.SameHost && e.Host != req.Host {
			continue
		}
		return true
	}
	return false
}
