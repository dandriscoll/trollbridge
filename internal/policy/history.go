package policy

import (
	"sync"
	"time"

	"github.com/dandriscoll/drawbridge/internal/types"
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
func (h *History) Record(req *types.RequestEvent, d types.Decision, when time.Time) {
	if h == nil {
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
