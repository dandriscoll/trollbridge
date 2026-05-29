package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// ANSI sentinels — pinned to the exact escape sequences the
// implementation must emit. Substring matches against these are
// not satisfied by any other ANSI escape the codebase uses today
// (greens, reds, yellows, cyans all differ in the trailing digit
// before `m`).
const (
	ansiYellow    = "\x1b[33m"  // human-pending / signaled
	ansiMagenta   = "\x1b[35m"  // LLM-checking (new)
	ansiGreen     = "\x1b[32m"  // running / 2xx
	ansiRed       = "\x1b[31m"  // denied / error / 4xx-5xx
	ansiReversal  = "\x1b[38;5;208m" // bright orange (new — reversal wrap)
	ansiResetCode = "\x1b[0m"
)

// staticHistory implements DecisionHistorySource for tests. Returns
// true when the (host, oppositeOf) pair was pre-loaded.
type staticHistory struct {
	priorByHost map[string]string // host → recent effect ("allow"/"deny")
}

func (s staticHistory) PriorOppositeEffect(host, currentEffect string) bool {
	prior, ok := s.priorByHost[host]
	if !ok {
		return false
	}
	if currentEffect == "" {
		return false
	}
	return prior != currentEffect
}

// TestColorizeStatus_LLMCheckingHasOwnColor pins the #192 color split:
// StatusChecking and StatusPending must render with distinct color
// prefixes (today they share yellow).
func TestColorizeStatus_LLMCheckingHasOwnColor(t *testing.T) {
	checking := colorizeStatus(opstream.StatusChecking)
	pending := colorizeStatus(opstream.StatusPending)

	if !strings.HasPrefix(checking, ansiMagenta) {
		t.Errorf("StatusChecking color = %q, want prefix %q", checking, ansiMagenta)
	}
	if !strings.HasPrefix(pending, ansiYellow) {
		t.Errorf("StatusPending color = %q, want prefix %q", pending, ansiYellow)
	}
	if strings.HasPrefix(checking, ansiYellow) {
		t.Errorf("StatusChecking still rendered in yellow (%q) — split did not land", checking)
	}
}

// TestColorizeStatusForRow_LLMSpinnerCyclesPerTick pins the
// per-tick animation: same op + status, varying tick counts produce
// distinct glyphs at deterministic frame indices.
func TestColorizeStatusForRow_LLMSpinnerCyclesPerTick(t *testing.T) {
	// Frame set (must match the implementation's spinner glyphs).
	wantFrames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴'}
	for tick := 0; tick < len(wantFrames)*2; tick++ {
		out := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", tick, nil)
		want := wantFrames[tick%len(wantFrames)]
		if !strings.ContainsRune(out, want) {
			t.Errorf("tick %d: rendered %q does not contain expected frame %q (frame index %d)",
				tick, out, want, tick%len(wantFrames))
		}
	}
	// Cross-check that two adjacent ticks render DIFFERENT glyphs
	// (catches a single-frame stuck implementation).
	a := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", 0, nil)
	b := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", 1, nil)
	if a == b {
		t.Errorf("spinner did not advance between tick 0 and tick 1: %q == %q", a, b)
	}
}

// TestColorizeStatusForRow_NoSpinnerForPending pins that the
// animation only applies to StatusChecking, not StatusPending.
// Operator-waiting must remain static.
func TestColorizeStatusForRow_NoSpinnerForPending(t *testing.T) {
	a := colorizeStatusForRow(opstream.StatusPending, "example.com", "", 0, nil)
	b := colorizeStatusForRow(opstream.StatusPending, "example.com", "", 5, nil)
	if a != b {
		t.Errorf("StatusPending changed between ticks (a=%q b=%q); pending must not animate", a, b)
	}
}

// TestColorizeStatusForRow_ReversalWrapsResolvedAllow:
// a 2xx op on a host with a recent deny in history must render
// with both the reversal-wrap escape AND the per-status green inside.
// Insight #40 fixture discipline: prior effect is "deny", current
// is the derived "allow"; the wrap fires only because the lookup
// found an opposite-effect entry.
func TestColorizeStatusForRow_ReversalWrapsResolvedAllow(t *testing.T) {
	hist := staticHistory{priorByHost: map[string]string{"b.example": "deny"}}
	out := colorizeStatusForRow("200", "b.example", "allow", 0, hist)
	if !strings.Contains(out, ansiReversal) {
		t.Errorf("reversal wrap missing for 200 on host with prior deny; out=%q want contains %q", out, ansiReversal)
	}
	if !strings.Contains(out, ansiGreen) {
		t.Errorf("per-status green missing inside reversal wrap; out=%q want contains %q", out, ansiGreen)
	}
}

// TestColorizeStatusForRow_ReversalWrapsResolvedDeny: symmetric —
// denied op on a host with prior allow → reversal wrap + red.
func TestColorizeStatusForRow_ReversalWrapsResolvedDeny(t *testing.T) {
	hist := staticHistory{priorByHost: map[string]string{"b.example": "allow"}}
	out := colorizeStatusForRow(opstream.StatusDenied, "b.example", "deny", 0, hist)
	if !strings.Contains(out, ansiReversal) {
		t.Errorf("reversal wrap missing for StatusDenied on host with prior allow; out=%q", out)
	}
	if !strings.Contains(out, ansiRed) {
		t.Errorf("per-status red missing inside reversal wrap; out=%q", out)
	}
}

// TestColorizeStatusForRow_NoReversalWhenHistoryEmpty: same resolved
// op, no prior decision in history → no reversal wrap.
func TestColorizeStatusForRow_NoReversalWhenHistoryEmpty(t *testing.T) {
	hist := staticHistory{} // empty
	out := colorizeStatusForRow("200", "b.example", "allow", 0, hist)
	if strings.Contains(out, ansiReversal) {
		t.Errorf("reversal wrap fired with empty history; out=%q", out)
	}
}

// TestColorizeStatusForRow_NoReversalWhenHistoryMatches: same effect
// in prior history → no reversal (the operator is being consistent).
func TestColorizeStatusForRow_NoReversalWhenHistoryMatches(t *testing.T) {
	hist := staticHistory{priorByHost: map[string]string{"b.example": "allow"}}
	out := colorizeStatusForRow("200", "b.example", "allow", 0, hist)
	if strings.Contains(out, ansiReversal) {
		t.Errorf("reversal wrap fired when prior matches current; out=%q", out)
	}
}

// TestColorizeStatusForRow_NoReversalForCheckingOrPending: pre-
// decision rows have no effect — reversal must not fire even when
// history would otherwise return true.
func TestColorizeStatusForRow_NoReversalForCheckingOrPending(t *testing.T) {
	hist := staticHistory{priorByHost: map[string]string{"b.example": "deny"}}
	for _, s := range []string{opstream.StatusChecking, opstream.StatusPending, opstream.StatusSignaled} {
		out := colorizeStatusForRow(s, "b.example", "", 0, hist)
		if strings.Contains(out, ansiReversal) {
			t.Errorf("reversal wrap fired for pre-decision status %q; out=%q", s, out)
		}
	}
}

// TestColorizeStatusForRow_NilHistoryIsSafe: nil DecisionHistorySource
// (attach mode) must short-circuit without panicking.
func TestColorizeStatusForRow_NilHistoryIsSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("colorizeStatusForRow panicked with nil history: %v", r)
		}
	}()
	out := colorizeStatusForRow("200", "b.example", "allow", 0, nil)
	if !strings.HasPrefix(out, ansiGreen) {
		t.Errorf("nil-history path lost the per-status color; out=%q", out)
	}
	if strings.Contains(out, ansiReversal) {
		t.Errorf("nil-history path produced reversal wrap: %q", out)
	}
}

// TestApplyOpsTick_IncrementsTickCount pins the tick-counter
// invariant: each tick advances Model.TickCount by 1, driving
// the spinner animation.
func TestApplyOpsTick_IncrementsTickCount(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{Ops: []opstream.Op{opAt("r", "GET", "https://x.example/", "200", "", t0)}}
	if m.TickCount != 0 {
		t.Fatalf("pre TickCount = %d, want 0", m.TickCount)
	}
	m, _ = applyOpsTick(m, OpsTickResult{Ops: m.Ops})
	if m.TickCount != 1 {
		t.Errorf("after 1st tick TickCount = %d, want 1", m.TickCount)
	}
	m, _ = applyOpsTick(m, OpsTickResult{Ops: m.Ops})
	if m.TickCount != 2 {
		t.Errorf("after 2nd tick TickCount = %d, want 2", m.TickCount)
	}
}

// TestApplyOpsTick_PausedTickDoesNotAdvanceTickCount: when the
// operator is navigating (OpsPausedTicks > 0), the tick is consumed
// for the pause counter but TickCount must not advance — otherwise
// the spinner would keep moving while the rest of the pane is
// frozen, which is jarring.
func TestApplyOpsTick_PausedTickDoesNotAdvanceTickCount(t *testing.T) {
	m := Model{OpsPausedTicks: 2}
	m, _ = applyOpsTick(m, OpsTickResult{Ops: nil})
	if m.TickCount != 0 {
		t.Errorf("paused tick advanced TickCount to %d, want 0", m.TickCount)
	}
	if m.OpsPausedTicks != 1 {
		t.Errorf("paused tick did not decrement OpsPausedTicks; got %d, want 1", m.OpsPausedTicks)
	}
}
