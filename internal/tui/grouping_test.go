package tui

import (
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestDisplayedOps_GroupsIdenticalMethodURL pins #63: three ops with
// the same (Method, URL) collapse to one row with Count=3; the
// representative is the newest by UpdatedAt.
func TestDisplayedOps_GroupsIdenticalMethodURL(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "c", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "b", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
			{RequestID: "a", Method: "GET", URL: "https://api.example.com/x", Status: "200", UpdatedAt: t0},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 1 {
		t.Fatalf("groups len = %d, want 1", len(got))
	}
	if got[0].Count != 3 {
		t.Errorf("Count = %d, want 3", got[0].Count)
	}
	if got[0].RequestID != "c" {
		t.Errorf("representative RequestID = %q, want %q (newest)", got[0].RequestID, "c")
	}
}

// TestDisplayedOps_DistinctURLsStayDistinct — two URLs → two rows.
func TestDisplayedOps_DistinctURLsStayDistinct(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	m := Model{
		Ops: []opstream.Op{
			{RequestID: "x1", Method: "GET", URL: "https://a/", Status: "200", UpdatedAt: t0.Add(2 * time.Second)},
			{RequestID: "y1", Method: "GET", URL: "https://b/", Status: "200", UpdatedAt: t0.Add(1 * time.Second)},
		},
	}
	got := DisplayedOps(m)
	if len(got) != 2 {
		t.Fatalf("groups len = %d, want 2", len(got))
	}
	for _, o := range got {
		if o.Count != 1 {
			t.Errorf("Count = %d for %q, want 1", o.Count, o.URL)
		}
	}
}

// TestBrailleCounter_LogScaleAndCap pins the logarithmic scale and
// 8-dot cap.
func TestBrailleCounter_LogScaleAndCap(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, " "},
		{1, " "},
		{2, "⠁"},
		{3, "⠁"},
		{4, "⠃"},
		{7, "⠃"},
		{8, "⠇"},
		{15, "⠇"},
		{16, "⠏"},
		{32, "⠟"},
		{64, "⠿"},
		{128, "⡿"},
		{256, "⣿"},
		{4096, "⣿"},
	}
	for _, tc := range cases {
		if got := brailleCounter(tc.n); got != tc.want {
			t.Errorf("brailleCounter(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
