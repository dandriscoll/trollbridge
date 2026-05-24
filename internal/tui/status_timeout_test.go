package tui

import "testing"

// TestStatusInfoTimesOut pins #180: a transient LastInfo line clears
// after the timeout instead of lingering at the bottom of the pane
// indefinitely.
func TestStatusInfoTimesOut(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, LastInfo: "generalized → allow GET api.example.com/v1/users/*"}

	// One tick registers the message; it should still be visible.
	m, _ = Apply(m, OpsTickResult{})
	if m.LastInfo == "" {
		t.Fatal("info cleared immediately; should dwell first")
	}

	// Keep ticking past the timeout; it must clear.
	for i := 0; i < statusInfoTimeoutTicks+1; i++ {
		m, _ = Apply(m, OpsTickResult{})
	}
	if m.LastInfo != "" {
		t.Errorf("info did not time out after ~%d ticks: %q", statusInfoTimeoutTicks, m.LastInfo)
	}
}

// TestStatusInfoTimeoutResetsOnNewMessage verifies each new message gets
// its full dwell (the age resets when the text changes).
func TestStatusInfoTimeoutResetsOnNewMessage(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, LastInfo: "first"}
	// Age "first" partway.
	for i := 0; i < statusInfoTimeoutTicks-1; i++ {
		m, _ = Apply(m, OpsTickResult{})
	}
	// A new message arrives — its dwell restarts.
	m.LastInfo = "second"
	m, _ = Apply(m, OpsTickResult{}) // registers "second", age 0
	m, _ = Apply(m, OpsTickResult{}) // age 1
	if m.LastInfo != "second" {
		t.Errorf("new message cleared too early (age not reset): %q", m.LastInfo)
	}
}
