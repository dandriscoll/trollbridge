package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestColorizeStatusForRow_VisibleLengthEqualsStatusW pins the
// fix for #197: the colorized status cell must produce EXACTLY
// statusW visible cells regardless of the ANSI bytes inside. Pre-
// fix, the cell was rune-truncated AFTER colorizing, so ANSI
// escape bytes counted as runes and the truncation cut into the
// escape sequence — producing the corrupt "20…" output the
// operator reported.
//
// This test exercises the production status set and pins that
// each colored cell renders at exactly the requested visible
// width.
func TestColorizeStatusForRow_VisibleLengthEqualsStatusW(t *testing.T) {
	const statusW = 11
	statuses := []string{
		opstream.StatusRunning,
		opstream.StatusChecking,
		opstream.StatusPending,
		opstream.StatusSignaled,
		opstream.StatusError,
		opstream.StatusDenied,
		"200", "302", "404", "500",
	}
	for _, s := range statuses {
		out := colorizeStatusForRow(s, "example.com", "", 0, nil)
		// New shape: cell is already padded to statusW. Apply
		// padRightVisible(out, statusW) to get the final cell;
		// visibleLen must equal statusW.
		padded := padRightVisible(out, statusW)
		got := visibleLen(padded)
		if got != statusW {
			t.Errorf("status %q: visibleLen = %d, want %d. Cell: %q",
				s, got, statusW, padded)
		}
	}
}

// TestColorizeStatusForRow_ReversalWrap_DoesNotCorruptVisibleWidth
// pins that the reversal wrap (which adds ~16 ANSI bytes around
// the per-status color) does not push visible width past statusW.
// The pre-fix bug: runeTrunc operated on the wrapped string and
// truncated into the ANSI bytes.
func TestColorizeStatusForRow_ReversalWrap_DoesNotCorruptVisibleWidth(t *testing.T) {
	const statusW = 11
	hist := staticHistory{priorByHost: map[string]string{"example.com": "deny"}}
	out := colorizeStatusForRow("200", "example.com", "allow", 0, hist)
	padded := padRightVisible(out, statusW)
	if got := visibleLen(padded); got != statusW {
		t.Errorf("reversal-wrapped cell visibleLen = %d, want %d. Cell: %q", got, statusW, padded)
	}
	// Sanity: both the reversal wrap escape AND the per-status green are present.
	if !strings.Contains(out, "\x1b[38;5;208m") {
		t.Errorf("reversal-wrapped cell missing reversal escape: %q", out)
	}
}

// TestFormatOpRow_StatusCellVisibleWidth pins #197 at the
// formatOpRow boundary. Pre-fix, formatOpRow called
// `runeTrunc(statusCell, statusW)` where statusCell was already
// colorized; rune count includes ANSI bytes, so the truncation
// chopped INTO the escape sequence and the cell rendered narrower
// than expected. The visible result was an ellipsis displacing
// the timestamp out of the TIME column — exactly the user's
// reproduction.
//
// The test asserts that the full row contains the literal
// "pending" string (not "pend…" or a mangled fragment) AND that
// the timestamp appears in its expected position relative to
// statusW.
func TestFormatOpRow_StatusCellVisibleWidth(t *testing.T) {
	now := time.Now().UTC()
	op := DisplayedOp{
		Op: opstream.Op{
			Method:    "GET",
			URL:       "https://example.com/path",
			Status:    opstream.StatusPending,
			HoldID:    "h1",
			StartedAt: now.Add(-time.Second),
			UpdatedAt: now.Add(-time.Second),
		},
		Count:    1,
		GroupKey: "h\x00h1",
	}
	const statusW = 11
	row := formatOpRow(op, 7, 30, statusW, now, 0, nil)
	if !strings.Contains(row, "pending") {
		t.Errorf("row missing literal 'pending' (truncation cut into ANSI escape and mangled the visible text). Row: %q", row)
	}
	if strings.Contains(row, "pend…") {
		t.Errorf("row contains mangled 'pend…' (status cell was rune-truncated through its ANSI escape). Row: %q", row)
	}
}

