package server

import (
	"sync"
	"time"
)

// openModeIncrements is the escalating add-amount sequence for repeated
// "open" presses (#209): the first press opens for 1 minute, and each
// further press adds the next amount — +1, +3, +5, +20, +30 — capped at
// +30 for any press beyond the sixth. pressCount resets once the window
// has expired, so a fresh open always starts at 1 minute.
var openModeIncrements = []time.Duration{
	1 * time.Minute,
	1 * time.Minute,
	3 * time.Minute,
	5 * time.Minute,
	20 * time.Minute,
	30 * time.Minute,
}

// openMode is the proxy's time-boxed "allow all traffic" window (#209).
// While active, the decision path allows every request (source
// open_mode) WITHOUT modifying the allow/deny lists; it reverts
// automatically at `until`. The zero value is a closed window.
type openMode struct {
	mu         sync.Mutex
	until      time.Time
	pressCount int
}

// extend opens the window (first press) or extends it (subsequent
// presses) and returns the new expiry. It adds to the remaining time
// (base = max(now, until)) so a press while open lengthens the window;
// if the window had already lapsed, the escalation resets so the next
// open starts at 1 minute.
func (o *openMode) extend(now time.Time) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !now.Before(o.until) { // expired or never opened
		o.pressCount = 0
	}
	idx := o.pressCount
	if idx >= len(openModeIncrements) {
		idx = len(openModeIncrements) - 1
	}
	base := o.until
	if now.After(base) {
		base = now
	}
	o.until = base.Add(openModeIncrements[idx])
	o.pressCount++
	return o.until
}

// close ends the window immediately and resets the escalation.
func (o *openMode) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.until = time.Time{}
	o.pressCount = 0
}

// state reports whether the window is open at `now` and its expiry.
func (o *openMode) state(now time.Time) (active bool, until time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return now.Before(o.until), o.until
}
