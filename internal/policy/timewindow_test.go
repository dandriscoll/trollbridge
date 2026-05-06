package policy

import (
	"testing"
	"time"
)

func mustTime(t *testing.T, layout, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(layout, s)
	if err != nil {
		t.Fatal(err)
	}
	return tt
}

func TestTimeWindow_HoursOnly(t *testing.T) {
	w := &TimeWindow{Hours: "09:00-17:00", TZ: "UTC"}
	cases := []struct {
		when string
		in   bool
	}{
		{"2026-05-06T08:59:00Z", false},
		{"2026-05-06T09:00:00Z", true},
		{"2026-05-06T16:59:59Z", true},
		{"2026-05-06T17:00:00Z", false},
		{"2026-05-06T23:30:00Z", false},
	}
	for _, c := range cases {
		got := w.inWindow(mustTime(t, time.RFC3339, c.when))
		if got != c.in {
			t.Errorf("inWindow(%s) = %v, want %v", c.when, got, c.in)
		}
	}
}

func TestTimeWindow_Weekdays(t *testing.T) {
	w := &TimeWindow{Weekdays: []string{"Mon", "Tue", "Wed", "Thu", "Fri"}, TZ: "UTC"}
	cases := []struct {
		when string
		in   bool
	}{
		{"2026-05-06T12:00:00Z", true},  // Wed
		{"2026-05-09T12:00:00Z", false}, // Sat
		{"2026-05-10T12:00:00Z", false}, // Sun
	}
	for _, c := range cases {
		got := w.inWindow(mustTime(t, time.RFC3339, c.when))
		if got != c.in {
			t.Errorf("inWindow(%s) = %v, want %v", c.when, got, c.in)
		}
	}
}

func TestTimeWindow_WrapsAroundMidnight(t *testing.T) {
	w := &TimeWindow{Hours: "22:00-04:00", TZ: "UTC"}
	if !w.inWindow(mustTime(t, time.RFC3339, "2026-05-06T23:30:00Z")) {
		t.Error("expected in-window at 23:30")
	}
	if !w.inWindow(mustTime(t, time.RFC3339, "2026-05-06T03:00:00Z")) {
		t.Error("expected in-window at 03:00")
	}
	if w.inWindow(mustTime(t, time.RFC3339, "2026-05-06T05:00:00Z")) {
		t.Error("did not expect in-window at 05:00")
	}
}
