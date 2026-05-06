// Package sessions tracks active client connections so the proxy can
// emit a stable session_id per TCP connection across the requests
// that flow over it.
package sessions

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session is one client TCP connection.
type Session struct {
	ID            string
	IdentityID    string
	ClientAddr    string
	StartedAt     time.Time
	LastActivity  time.Time
	DecisionCount int
}

// Tracker holds active sessions keyed by client connection address.
// Phase 2 keeps it simple: we look up by client RemoteAddr, which is
// stable for the life of the TCP connection in net/http.
type Tracker struct {
	mu       sync.Mutex
	byAddr   map[string]*Session
}

// New returns an empty tracker.
func New() *Tracker {
	return &Tracker{byAddr: map[string]*Session{}}
}

// GetOrCreate returns the session for clientAddr, creating one if
// missing.
func (t *Tracker) GetOrCreate(clientAddr, identityID string) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.byAddr[clientAddr]; ok {
		s.LastActivity = time.Now().UTC()
		s.DecisionCount++
		if identityID != "" && identityID != "anonymous" {
			s.IdentityID = identityID
		}
		return s
	}
	s := &Session{
		ID:           "sess-" + uuid.NewString(),
		IdentityID:   identityID,
		ClientAddr:   clientAddr,
		StartedAt:    time.Now().UTC(),
		LastActivity: time.Now().UTC(),
	}
	t.byAddr[clientAddr] = s
	return s
}

// Drop removes a session (called when its connection closes).
func (t *Tracker) Drop(clientAddr string) {
	t.mu.Lock()
	delete(t.byAddr, clientAddr)
	t.mu.Unlock()
}

// Snapshot returns a copy of all active sessions.
func (t *Tracker) Snapshot() []Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Session, 0, len(t.byAddr))
	for _, s := range t.byAddr {
		out = append(out, *s)
	}
	return out
}
