package tui

import (
	"strings"
	"testing"
	"time"
)

// TestFormatOpTime pins #67: same-day → HH:MM:SS; different day →
// MM-DD HH:MM:SS; year always omitted.
func TestFormatOpTime(t *testing.T) {
	// Pick a fixed "now" in local time so format strings are stable.
	now := time.Date(2026, 5, 11, 14, 30, 0, 0, time.Local)

	cases := []struct {
		name   string
		t      time.Time
		want   string
		reject string
	}{
		{
			name: "same day later in afternoon",
			t:    time.Date(2026, 5, 11, 9, 15, 42, 0, time.Local),
			want: "09:15:42",
		},
		{
			name: "yesterday",
			t:    time.Date(2026, 5, 10, 23, 59, 59, 0, time.Local),
			want: "05-10 23:59:59",
		},
		{
			name: "last year, no year in output",
			t:    time.Date(2025, 12, 31, 12, 0, 0, 0, time.Local),
			want: "12-31 12:00:00",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatOpTime(tc.t, now)
			if got != tc.want {
				t.Errorf("formatOpTime = %q, want %q", got, tc.want)
			}
			// Year must never appear in the output.
			if strings.Contains(got, "2026") || strings.Contains(got, "2025") {
				t.Errorf("output contains a year: %q", got)
			}
		})
	}
}
