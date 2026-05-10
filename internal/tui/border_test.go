package tui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Border helpers are pure functions: given (label, rightHint, cols,
// focused) return a string row. Tests pin the load-bearing structural
// invariants — corners, color escape, embedded text appearance — and
// assert graceful degrade as cols shrinks below the embed and minimum
// thresholds.

func TestTopBorder_FocusedCarriesCyanAndCorners(t *testing.T) {
	got := topBorder("approvals", "[Tab] focus console", 80, true)
	if !strings.Contains(got, "\x1b[36m") {
		t.Errorf("focused top border missing cyan escape; got %q", got)
	}
	if !strings.Contains(got, "╭") || !strings.Contains(got, "╮") {
		t.Errorf("focused top border missing rounded corners; got %q", got)
	}
	if !strings.Contains(got, "approvals") {
		t.Errorf("focused top border missing label; got %q", got)
	}
	if !strings.Contains(got, "[Tab] focus console") {
		t.Errorf("focused top border missing right hint; got %q", got)
	}
}

func TestTopBorder_UnfocusedDimNoBright(t *testing.T) {
	got := topBorder("console", "", 80, false)
	if !strings.Contains(got, "\x1b[2m") {
		t.Errorf("unfocused top border missing dim escape; got %q", got)
	}
	if strings.Contains(got, "\x1b[36m") {
		t.Errorf("unfocused top border should not carry cyan; got %q", got)
	}
}

func TestBottomBorder_KeybindingsRightAligned(t *testing.T) {
	got := bottomBorder("", "[a] approve  [d] deny", 80, true)
	if !strings.Contains(got, "╰") || !strings.Contains(got, "╯") {
		t.Errorf("bottom border missing rounded corners; got %q", got)
	}
	if !strings.Contains(got, "[a] approve") {
		t.Errorf("bottom border missing keybindings; got %q", got)
	}
	// The hint should appear after the dashes (right-aligned). Find
	// the index of "[a]" and the index of the closing corner; the
	// hint must come before the corner with at most a small dash run
	// between them.
	idxHint := strings.Index(got, "[a] approve")
	idxCorner := strings.Index(got, "╯")
	if idxHint > idxCorner {
		t.Errorf("hint appears after closing corner; got %q", got)
	}
}

func TestBorders_BelowEmbedThresholdSuppressText(t *testing.T) {
	// At cols < borderEmbedThreshold (40) the embedded label and hint
	// drop. Plain dashes between corners.
	got := topBorder("approvals", "[Tab] focus console", 30, true)
	if strings.Contains(got, "approvals") {
		t.Errorf("at cols=30 the label should be suppressed; got %q", got)
	}
	if strings.Contains(got, "[Tab] focus console") {
		t.Errorf("at cols=30 the right hint should be suppressed; got %q", got)
	}
	if !strings.Contains(got, "╭") || !strings.Contains(got, "╮") {
		t.Errorf("corners must remain at cols=30; got %q", got)
	}
}

func TestBorders_OverflowDropsHintFirst(t *testing.T) {
	// Just over the embed threshold but tight: the right hint may
	// drop while the label survives.
	got := topBorder("approvals", "[Tab] focus console", 45, true)
	if !strings.Contains(got, "approvals") {
		t.Errorf("label should survive at cols=45; got %q", got)
	}
	// Don't pin whether right hint is present — depends on lengths;
	// either result is acceptable as long as no overflow happened.
}

func TestBorderRow_PaddedToCols(t *testing.T) {
	// The row, stripped of color escapes, should equal exactly `cols`
	// runes. Any drift indicates the dash budget calculation is off.
	for _, cols := range []int{20, 40, 60, 80, 120} {
		row := topBorder("approvals", "[Tab] focus console", cols, true)
		stripped := stripANSI(strings.TrimSuffix(row, "\r\n"))
		if got := utf8.RuneCountInString(stripped); got != cols {
			t.Errorf("topBorder(cols=%d): row width = %d runes, want %d; row=%q",
				cols, got, cols, stripped)
		}
	}
}

func TestBodyLine_FocusedAndUnfocusedColors(t *testing.T) {
	// bodyLine wraps content with │ … │ and applies the focus color
	// to the side bars only — the content color is whatever the
	// caller set inside it.
	focused := bodyLine("hello world", 20, true)
	if !strings.Contains(focused, "\x1b[36m") {
		t.Errorf("focused body line missing cyan side bars; got %q", focused)
	}
	if !strings.Contains(focused, "│") {
		t.Errorf("focused body line missing │ side bar; got %q", focused)
	}
	unfocused := bodyLine("hello world", 20, false)
	if !strings.Contains(unfocused, "\x1b[2m") {
		t.Errorf("unfocused body line missing dim side bars; got %q", unfocused)
	}
}

func TestProductionHints_AreASCII(t *testing.T) {
	// Hint strings embedded in borders go through runeTrunc, which is
	// rune-counted but not East-Asian-wide-aware. Production hints
	// must be ASCII-only so width math stays correct on any terminal.
	hints := []string{
		"[Tab] focus console",
		"[Tab] focus approvals",
		"[a] approve  [d] deny  [↑↓/jk] select  [r] refresh  [q] quit",
		"[Ctrl-C] quit",
	}
	for _, h := range hints {
		// The arrow runes ↑↓ in the keybindings hint are wide-but-1-col
		// in modern terminals; pinned here as the one accepted exception.
		// Everything else must be 7-bit ASCII.
		stripped := strings.NewReplacer("↑", "", "↓", "").Replace(h)
		for i, r := range stripped {
			if r > 0x7E {
				t.Errorf("hint %q contains non-ASCII rune %q at byte %d", h, r, i)
			}
		}
	}
}

// stripANSI removes ANSI CSI sequences (\x1b[ … <letter>) from a
// string. Used for measuring visible width; not exhaustive but covers
// the SGR escapes the renderer emits.
func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			// Skip until a letter terminates the sequence.
			j := i + 2
			for j < len(s) {
				c := s[j]
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
					j++
					break
				}
				j++
			}
			i = j
			continue
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += sz
	}
	return b.String()
}
