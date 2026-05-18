// Package advisor — digest ring. Captures every Classify call's
// outcome (timestamp, request summary, effect, confidence,
// advisor_id, justification) in a bounded in-memory ring so the
// operator can browse recent LLM evaluations (closes #65). The
// audit log remains the durable record; this ring is the
// rolling-window view the TUI's #66 LLM panel will read.
package advisor

import (
	"sync"
	"time"
)

// DigestDefaultCap is the default ring capacity. Picked to match
// opstream.DefaultCap; the audit log is the durable record so the
// ring just needs enough depth for an operator scrolling back
// through "what just happened."
const DigestDefaultCap = 100

// DigestOutcome strings identify which advisor exit path produced
// the entry.
const (
	DigestOutcomeClassified       = "classified"
	DigestOutcomeUnavailable      = "unavailable"
	DigestOutcomeValidationFailed = "validation-failed"
)

// Digest is one Classify call's recorded outcome.
type Digest struct {
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id"`
	Method     string    `json:"method"`
	Scheme     string    `json:"scheme"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Path       string    `json:"path,omitempty"`
	Effect     string    `json:"effect"`
	Confidence string    `json:"confidence,omitempty"`
	AdvisorID  string    `json:"advisor_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Outcome    string    `json:"outcome"`
	// LLMInputHash is the hash of the advisor's request payload,
	// shared with the audit entry that triggered the Classify call.
	// Lets an operator grep across the digest ring and the audit
	// log with a single key to correlate one decision (#137).
	LLMInputHash string `json:"llm_input_hash,omitempty"`
}

// DigestRing is a bounded, append-only ring of recent Digest entries.
// Safe for concurrent use.
type DigestRing struct {
	mu    sync.Mutex
	cap   int
	items []Digest
}

// NewDigestRing returns a ring with the given capacity. cap <= 0
// falls back to DigestDefaultCap.
func NewDigestRing(cap int) *DigestRing {
	if cap <= 0 {
		cap = DigestDefaultCap
	}
	return &DigestRing{cap: cap, items: make([]Digest, 0, cap)}
}

// Add records a digest, evicting the oldest entry when at cap.
func (r *DigestRing) Add(d Digest) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.cap {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, d)
}

// Snapshot returns a copy of the current entries, oldest-first.
// The returned slice does not alias ring state.
func (r *DigestRing) Snapshot() []Digest {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Digest, len(r.items))
	copy(out, r.items)
	return out
}
