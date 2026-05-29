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

// TestColorizeStatusForRow_LLMUsesBlinkAndDistinctTerm pins the
// post-#192-reopen rendering: the prior per-tick Braille spinner
// was too subtle ("one frame per 1.5s"), so it's been replaced
// with the ANSI blink escape (SGR 5 = "\x1b[5m") combined with
// magenta (35) and the distinct term "thinking" (so the operator
// sees something visibly different from a static yellow
// "pending" — and waiting-on-LLM reads differently from
// waiting-on-human).
//
// The blink is terminal-managed and immediate — no tick-driven
// frame cycling.
func TestColorizeStatusForRow_LLMUsesBlinkAndDistinctTerm(t *testing.T) {
	out := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", 0, nil)
	// Must contain the SGR-5 blink escape.
	if !strings.Contains(out, "\x1b[35;5m") {
		t.Errorf("LLM-checking render missing the SGR-5 blink escape; out=%q", out)
	}
	// Must contain the distinct term "thinking" (not "checking").
	if !strings.Contains(out, "thinking") {
		t.Errorf("LLM-checking render missing the distinct term 'thinking'; out=%q", out)
	}
	if strings.Contains(out, "checking") {
		t.Errorf("LLM-checking render still says 'checking' — the wire-format value leaked through "+
			"the render-time substitution; out=%q", out)
	}
	// Adjacent ticks should render IDENTICALLY (blink is terminal-
	// managed, not tick-driven). This is a positive assertion of
	// the new design: no tick-dependence in the LLM-checking cell.
	a := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", 0, nil)
	b := colorizeStatusForRow(opstream.StatusChecking, "example.com", "", 100, nil)
	if a != b {
		t.Errorf("LLM-checking render changed between ticks (no longer tick-driven post-#192-reopen); a=%q b=%q", a, b)
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

// TestExtractHostForStatusColor_StripsPort pins the #192 reopen
// fix: extractHostForStatusColor must return the host WITHOUT
// the port, because policy.History stores `req.Host` as hostname
// only (port is a separate field). Pre-fix, this returned
// "example.com:443" and never matched stored "example.com"
// entries — reversal lookup silently returned false.
func TestExtractHostForStatusColor_StripsPort(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://example.com:443/path", "example.com"},
		{"http://example.com:8080/api", "example.com"},
		{"https://example.com/", "example.com"},
		// IPv6 with bracketed host + port.
		{"https://[::1]:443/p", "::1"},
	}
	for _, c := range cases {
		got := extractHostForStatusColor(c.url)
		if got != c.want {
			t.Errorf("extractHostForStatusColor(%q) = %q; want %q", c.url, got, c.want)
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
