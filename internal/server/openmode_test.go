package server

import (
	"testing"
	"time"
)

// TestOpenMode_EscalationSequence pins #209's add-amount escalation:
// first open = 1m, then +1, +3, +5, +20, +30, capped at +30. Presses
// happen while the window is still open, so each adds to the remaining
// time.
func TestOpenMode_EscalationSequence(t *testing.T) {
	var o openMode
	base := time.Unix(1_700_000_000, 0).UTC()
	// All presses happen "now" while the window stays open (base never
	// advances past until), so each press adds the next increment.
	wantAddMins := []int{1, 1, 3, 5, 20, 30, 30, 30}
	cum := 0
	for i, add := range wantAddMins {
		until := o.extend(base)
		cum += add
		gotMins := int(until.Sub(base).Minutes())
		if gotMins != cum {
			t.Fatalf("press %d: until=+%dm, want cumulative +%dm (add %dm)", i+1, gotMins, cum, add)
		}
	}
}

// TestOpenMode_ResetsAfterExpiry: once the window lapses, the next open
// starts the escalation over at 1 minute.
func TestOpenMode_ResetsAfterExpiry(t *testing.T) {
	var o openMode
	t0 := time.Unix(1_700_000_000, 0).UTC()
	o.extend(t0)        // open 1m -> until = t0+1m
	o.extend(t0)        // +1m while open -> +2m total
	later := t0.Add(10 * time.Minute) // well past expiry
	until := o.extend(later)
	if got := int(until.Sub(later).Minutes()); got != 1 {
		t.Fatalf("fresh open after expiry = +%dm, want +1m (escalation must reset)", got)
	}
}

// TestOpenMode_StateAndClose: state() tracks active/expiry; close()
// ends the window immediately and resets escalation.
func TestOpenMode_StateAndClose(t *testing.T) {
	var o openMode
	t0 := time.Unix(1_700_000_000, 0).UTC()
	if active, _ := o.state(t0); active {
		t.Fatal("zero-value openMode should be closed")
	}
	o.extend(t0)
	if active, until := o.state(t0); !active || !until.After(t0) {
		t.Fatalf("after extend: active=%v until=%v, want active with future until", active, until)
	}
	if active, _ := o.state(t0.Add(2 * time.Minute)); active {
		t.Fatal("window should have lapsed after its duration")
	}
	o.extend(t0)
	o.close()
	if active, _ := o.state(t0); active {
		t.Fatal("close() must end the window immediately")
	}
	// After close, escalation reset -> next open is 1m again.
	until := o.extend(t0)
	if got := int(until.Sub(t0).Minutes()); got != 1 {
		t.Fatalf("open after close = +%dm, want +1m", got)
	}
}
