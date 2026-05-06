package policy

import (
	"fmt"
	"strings"
	"time"
)

// inWindow returns true if t falls within the TimeWindow.
func (w *TimeWindow) inWindow(t time.Time) bool {
	loc := time.UTC
	if w.TZ != "" {
		if l, err := time.LoadLocation(w.TZ); err == nil {
			loc = l
		}
	}
	t = t.In(loc)

	if !weekdayMatch(t.Weekday(), w.Weekdays) {
		return false
	}
	if w.Hours == "" {
		return true
	}
	startMin, endMin, err := parseHourRange(w.Hours)
	if err != nil {
		return false
	}
	cur := t.Hour()*60 + t.Minute()
	if startMin <= endMin {
		return cur >= startMin && cur < endMin
	}
	// wrap-around (e.g. 22:00-04:00).
	return cur >= startMin || cur < endMin
}

func weekdayMatch(d time.Weekday, list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, w := range list {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "all" {
			return true
		}
		if w == strings.ToLower(d.String()[:3]) || w == strings.ToLower(d.String()) {
			return true
		}
	}
	return false
}

func parseHourRange(s string) (int, int, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid hours %q", s)
	}
	start, err := parseHHMM(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	end, err := parseHHMM(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func parseHHMM(s string) (int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	var h, m int
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil {
		return 0, err
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil {
		return 0, err
	}
	if h < 0 || h > 24 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	return h*60 + m, nil
}
