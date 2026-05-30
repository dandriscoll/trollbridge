package tui

import (
	"strings"
	"unicode/utf8"
)

// virtualScreen replays the byte stream a terminal would receive
// from the TUI renderer and returns the final visible screen state
// as one string per row.
//
// Recognized escape sequences (those writeFullFrame and
// writeDeltaFrame emit):
//   - \x1b[H            home cursor
//   - \x1b[2J           clear entire screen
//   - \x1b[3J           clear scrollback (ignored — no scrollback model)
//   - \x1b[<r>;1H       move cursor to row r (1-indexed), col 1
//   - \x1b[K            clear from cursor to end of line
//   - \x1b[?25l/h       hide/show cursor (ignored)
//   - \x1b[?1049l/h     alt-screen toggle (ignored)
//
// Color/style codes (\x1b[<N>m) are stripped so the returned text
// is comparable across renders that toggle focus colors. Other
// CSI sequences pass silently.
//
// Plain runes write at the cursor position (rune-indexed columns)
// and advance the column. Newlines move to col 0 of the next row.
//
// Pure test helper — used to verify that the line-delta path
// produces the same final screen state as the full-render path
// (closes #202 / Job 247 drift guard).
func virtualScreen(stream string, rows, cols int) []string {
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, cols)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}
	row, col := 0, 0
	i := 0
	for i < len(stream) {
		c := stream[i]
		if c == 0x1b && i+1 < len(stream) && stream[i+1] == '[' {
			j := i + 2
			for j < len(stream) {
				b := stream[j]
				if (b >= '0' && b <= '9') || b == ';' || b == '?' {
					j++
					continue
				}
				break
			}
			if j >= len(stream) {
				break
			}
			params := stream[i+2 : j]
			final := stream[j]
			i = j + 1
			handleCSI(grid, &row, &col, rows, cols, params, final)
			continue
		}
		if c == '\n' {
			row++
			col = 0
			i++
			continue
		}
		if c == '\r' {
			col = 0
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(stream[i:])
		if row >= 0 && row < rows && col >= 0 && col < cols {
			grid[row][col] = r
		}
		col++
		i += size
	}
	out := make([]string, rows)
	for i, line := range grid {
		out[i] = strings.TrimRight(string(line), " ")
	}
	return out
}

func handleCSI(grid [][]rune, row, col *int, rows, cols int, params string, final byte) {
	switch final {
	case 'H':
		if params == "" {
			*row = 0
			*col = 0
			return
		}
		r, c := 1, 1
		parts := strings.SplitN(params, ";", 2)
		if parts[0] != "" {
			r = atoi(parts[0])
			if r < 1 {
				r = 1
			}
		}
		if len(parts) == 2 && parts[1] != "" {
			c = atoi(parts[1])
			if c < 1 {
				c = 1
			}
		}
		*row = r - 1
		*col = c - 1
	case 'J':
		// \x1b[2J / \x1b[3J — wipe the visible grid; scrollback is
		// not modeled.
		if params == "2" || params == "3" {
			for i := range grid {
				for j := range grid[i] {
					grid[i][j] = ' '
				}
			}
		}
	case 'K':
		// Clear from cursor to end of line.
		if *row >= 0 && *row < rows {
			for j := *col; j < cols; j++ {
				grid[*row][j] = ' '
			}
		}
	default:
		// 'm' (SGR), '?25l/h', '?1049l/h', and any other CSI we
		// don't model — drop silently.
	}
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
