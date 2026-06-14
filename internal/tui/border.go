package tui

import (
	"fmt"
	"strings"
)

// Pane chrome is rendered with rounded box-drawing characters and a
// single color signal (bright cyan for focused, dim grey for
// unfocused) — same convention as btop, ranger, htop, lazygit. Help
// strings (pane keybindings, the Tab-focus cue, the Ctrl-C quit cue)
// embed into the border row of the pane they act on. The global hint
// row that lived at the bottom of the screen is gone; every help
// string is adjacent to the surface it changes.
//
// All three helpers return a string padded to exactly `cols` runes
// (followed by `\r\n`). Embedded label/hint text falls off according
// to two thresholds:
//
//   - cols < borderEmbedThreshold (40): no label or hint embedded;
//     plain dash row between the corners.
//   - cols < borderMinThreshold (20): caller is expected to fall back
//     to the no-border layout. Helpers do not enforce this; the
//     whole-screen render makes that decision.
//
// Selection inverse-video must be applied by the caller inside the
// content string before bodyLine wraps it: bodyLine treats `content`
// as opaque and computes width from rune count, which would be wrong
// if it had to interpret embedded escapes.

const (
	borderTopLeft     = "╭"
	borderTopRight    = "╮"
	borderBottomLeft  = "╰"
	borderBottomRight = "╯"
	borderHorizontal  = "─"
	borderVertical    = "│"

	// Color escapes: bright cyan for focused chrome, dim grey for
	// unfocused. Reset closes both.
	colorFocused   = "\x1b[36m"
	colorUnfocused = "\x1b[2m"
	colorReset     = "\x1b[0m"
	// colorOpenMode is the amber/yellow chrome color the approvals pane
	// border uses while the time-boxed "allow all traffic" window is
	// active (#209) — a persistent, distinct-from-focus signal that the
	// proxy is currently letting everything through.
	colorOpenMode = "\x1b[33m"

	// Below borderEmbedThreshold, label/hint text is suppressed and
	// only the dashes render. Below borderMinThreshold the caller
	// falls back to the no-border layout — see render() in approvals.go.
	borderEmbedThreshold = 40
	borderMinThreshold   = 20
)

// topBorder draws "╭─ <label> ─…─ <rightHint> ─╮" padded to cols.
// `label` lands left of the dashes; `rightHint` lands right. Either
// or both may be empty. When the column budget cannot fit them, they
// are suppressed in label-first / hint-first order.
func topBorder(label, rightHint string, cols int, focused bool) string {
	return topBorderC(label, rightHint, cols, chromeColor(focused))
}

// topBorderC is topBorder with an explicit chrome color, used where the
// color is not just focus-derived (the open-mode amber border, #209).
func topBorderC(label, rightHint string, cols int, color string) string {
	return borderRowC(borderTopLeft, borderTopRight, label, rightHint, cols, color)
}

// bottomBorder draws "╰─ <leftHint> ─…─ <rightHint> ─╯" padded to
// cols. Mirrors topBorder.
func bottomBorder(leftHint, rightHint string, cols int, focused bool) string {
	return bottomBorderC(leftHint, rightHint, cols, chromeColor(focused))
}

// bottomBorderC is bottomBorder with an explicit chrome color (#209).
func bottomBorderC(leftHint, rightHint string, cols int, color string) string {
	return borderRowC(borderBottomLeft, borderBottomRight, leftHint, rightHint, cols, color)
}

// chromeColor maps the focus flag to the default chrome color.
func chromeColor(focused bool) string {
	if focused {
		return colorFocused
	}
	return colorUnfocused
}

// bodyLine wraps content in │ … │ side borders, padded to cols.
// `content` may contain ANSI escapes for selection or color; the
// caller must compute its visible rune width and pass content already
// truncated/padded to (cols-2) cells if it depends on alignment. As a
// convenience, when content contains no escape sequences, bodyLine
// pads/truncates it itself.
func bodyLine(content string, cols int, focused bool) string {
	return bodyLineC(content, cols, chromeColor(focused))
}

// bodyLineC is bodyLine with an explicit side-border color (#209).
func bodyLineC(content string, cols int, color string) string {
	if cols < borderMinThreshold {
		// Below the no-border fallback threshold the caller should not
		// be invoking bodyLine; defensively pad content as a plain row.
		return padRight(runeTrunc(content, cols), cols) + "\r\n"
	}
	inner := cols - 2
	if inner < 1 {
		inner = 1
	}
	// Pad/truncate content to exactly `inner` visible cells. The fast
	// path (no ANSI escapes) is the common case; selection rows pre-wrap
	// their own \x1b[7m … \x1b[0m and pass an already-correctly-sized
	// string through.
	if !strings.ContainsRune(content, '\x1b') {
		content = padRight(runeTrunc(content, inner), inner)
	}
	return color + borderVertical + colorReset +
		content +
		color + borderVertical + colorReset +
		"\r\n"
}

// borderRow does the shared top/bottom layout. `left` and `right`
// are the corner runes; `leftText` / `rightText` are the embedded
// strings (label or hint). The middle is dash-filled.
func borderRow(left, right, leftText, rightText string, cols int, focused bool) string {
	return borderRowC(left, right, leftText, rightText, cols, chromeColor(focused))
}

// borderRowC is borderRow with an explicit color (#209).
func borderRowC(left, right, leftText, rightText string, cols int, color string) string {
	// At cols below the embed threshold, drop the embedded text and
	// render plain corners + dashes.
	if cols < borderEmbedThreshold {
		leftText = ""
		rightText = ""
	}
	// Layout: left-corner + dash + " " + leftText + " " + dashes +
	// " " + rightText + " " + dash + right-corner. Empty texts
	// collapse cleanly: " " + "" + " " degrades to "  " then dashes
	// fill the rest.
	leftSeg := ""
	rightSeg := ""
	if leftText != "" {
		leftSeg = " " + leftText + " "
	}
	if rightText != "" {
		rightSeg = " " + rightText + " "
	}
	// Total fixed cells: 2 corners + 1 dash on each side adjacent to
	// the corners + leftSeg + rightSeg.
	fixed := 2 + 1 + 1 + runeLen(leftSeg) + runeLen(rightSeg)
	// If the embedded text would overflow, drop it gracefully: try
	// hint-only, then label-only, then plain dashes. Ordering: keep
	// label preferentially (the pane name is more load-bearing than
	// the per-pane hint).
	if fixed > cols {
		// Try without the right hint.
		rightSeg = ""
		fixed = 2 + 1 + 1 + runeLen(leftSeg) + runeLen(rightSeg)
		if fixed > cols {
			leftSeg = ""
			fixed = 2 + 1 + 1
		}
	}
	dashCount := cols - fixed
	if dashCount < 0 {
		dashCount = 0
	}
	mid := strings.Repeat(borderHorizontal, dashCount)
	row := left + borderHorizontal + leftSeg + mid + rightSeg + borderHorizontal + right
	// Some terminals (or cols just-barely-too-small) may leave the row
	// short of cols; pad the visible text to cols cells before color
	// wraps. runeLen counts runes (no escapes present yet).
	if visible := runeLen(row); visible < cols {
		row += strings.Repeat(" ", cols-visible)
	} else if visible > cols {
		// Trim from the right while preserving the closing corner.
		runes := []rune(row)
		runes = append(runes[:cols-1], rune(right[0]))
		row = string(runes)
	}
	return color + row + colorReset + "\r\n"
}

// runeLen returns the number of runes in s. Defined here so border.go
// does not depend on internal helpers in approvals.go beyond the
// existing padRight/runeTrunc.
func runeLen(s string) int {
	return len([]rune(s))
}

// formatPaneLabel composes the pane title shown in the top-left of
// the top border. The focus marker survives from job 094 — the dim/
// bright color signal carries focus today, but the marker is kept for
// accessibility on terminals where the color difference is weak.
func formatPaneLabel(title string, focused bool) string {
	if focused {
		return "▶ " + title
	}
	return "  " + title
}

// formatTabHint returns the "[Tab] focus <next>" cue rendered into
// the focused pane's top border at top-right.
func formatTabHint(currentFocus Pane) string {
	target := "console"
	if currentFocus == PaneConsole {
		target = "approvals"
	}
	return fmt.Sprintf("[Tab] focus %s", target)
}
