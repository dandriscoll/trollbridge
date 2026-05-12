package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

// TestApplyKey_RetroactiveAllow_SetsGeneralizeOffer pins #85: the
// 'a' press on a completed op writes the specific (method-prefixed)
// pattern AND sets the GeneralizeOffer for the renderer / next
// keystroke.
func TestApplyKey_RetroactiveAllow_SetsGeneralizeOffer(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "https://api.example.com:443/v1/users/42", Status: "200"},
		},
		Selected: 0,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 'a'})
	exec, ok := cmd.(CmdConsoleExec)
	if !ok {
		t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
	}
	if want := "allow GET https://api.example.com:443/v1/users/42"; exec.Line != want {
		t.Errorf("Line = %q, want %q", exec.Line, want)
	}
	if got.GeneralizeOffer == nil {
		t.Fatal("GeneralizeOffer not set after retroactive 'a'")
	}
	want := GeneralizeOffer{
		Method: "GET",
		URL:    "https://api.example.com:443/v1/users/42",
		Scheme: "https",
		Host:   "api.example.com",
		Port:   443,
		Path:   "/v1/users/42",
	}
	if *got.GeneralizeOffer != want {
		t.Errorf("GeneralizeOffer = %+v, want %+v", *got.GeneralizeOffer, want)
	}
}

// TestApplyKey_RetroactiveDeny_DoesNotSetOffer: 'd' writes the
// deny pattern but does NOT show the generalise prompt (denies are
// operator-narrow today).
func TestApplyKey_RetroactiveDeny_DoesNotSetOffer(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "evil.example.com", Status: opstream.StatusDenied},
		},
		Selected: 0,
	}
	got, _ := Apply(m, KeyEvent{Rune: 'd'})
	if got.GeneralizeOffer != nil {
		t.Errorf("GeneralizeOffer should not be set for 'd'; got %+v", *got.GeneralizeOffer)
	}
}

// TestGeneralizeOffer_DigitsEmitBroaderPattern: the three digits
// each emit the corresponding broader allow pattern and clear the
// offer.
func TestGeneralizeOffer_DigitsEmitBroaderPattern(t *testing.T) {
	base := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	offer := &GeneralizeOffer{
		Method: "GET",
		URL:    "https://api.example.com:443/v1/users/42",
		Scheme: "https",
		Host:   "api.example.com",
		Port:   443,
		Path:   "/v1/users/42",
	}
	cases := []struct {
		key      rune
		wantLine string
	}{
		{'1', "allow * https://api.example.com:443/v1/users/42"},
		{'2', "allow GET https://api.example.com:443/*"},
		{'3', "allow * https://api.example.com:443/*"},
	}
	for _, tc := range cases {
		t.Run(string(tc.key), func(t *testing.T) {
			m := base
			m.GeneralizeOffer = offer
			got, cmd := Apply(m, KeyEvent{Rune: tc.key})
			exec, ok := cmd.(CmdConsoleExec)
			if !ok {
				t.Fatalf("cmd = %T, want CmdConsoleExec", cmd)
			}
			if exec.Line != tc.wantLine {
				t.Errorf("Line = %q, want %q", exec.Line, tc.wantLine)
			}
			if got.GeneralizeOffer != nil {
				t.Errorf("GeneralizeOffer should be cleared after digit press")
			}
		})
	}
}

// TestGeneralizeOffer_EscDismisses: Esc clears the offer without
// emitting a console exec. The Esc continues through the normal
// applyKey dispatch (e.g., quits when focused on approvals).
func TestGeneralizeOffer_EscDismisses(t *testing.T) {
	offer := &GeneralizeOffer{Method: "GET", URL: "https://x/", Scheme: "https", Host: "x", Port: 443, Path: "/"}
	m := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, GeneralizeOffer: offer}
	got, _ := Apply(m, KeyEvent{Key: KeyEsc})
	if got.GeneralizeOffer != nil {
		t.Errorf("Esc should have cleared GeneralizeOffer")
	}
	// LastInfo should name the dismissal so the operator sees a
	// confirmation, not a silent state change.
	if !strings.Contains(got.LastInfo, "dismissed") {
		t.Errorf("LastInfo = %q, want it to mention dismissal", got.LastInfo)
	}
}

// TestGeneralizeOffer_NavigationKeyDismisses: pressing j/k while
// the offer is up clears the offer; the navigation also takes
// effect (the keystroke falls through).
func TestGeneralizeOffer_NavigationKeyDismisses(t *testing.T) {
	offer := &GeneralizeOffer{Method: "GET", URL: "https://x/", Scheme: "https", Host: "x", Port: 443, Path: "/"}
	m := Model{
		Cols: 100, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "https://a/", Status: "200"},
			{RequestID: "r2", Method: "GET", URL: "https://b/", Status: "200"},
		},
		Selected:        0,
		GeneralizeOffer: offer,
	}
	got, _ := Apply(m, KeyEvent{Rune: 'j'})
	if got.GeneralizeOffer != nil {
		t.Errorf("'j' should have cleared the offer")
	}
	if got.Selected != 1 {
		t.Errorf("'j' should have advanced Selected; got %d, want 1", got.Selected)
	}
}

// TestRender_GeneralizeOfferStatusRow: the rendered approvals
// pane status row carries the offer prompt while
// GeneralizeOffer is set.
func TestRender_GeneralizeOfferStatusRow(t *testing.T) {
	m := Model{
		Cols: 120, Rows: 30, Focused: PaneApprovals,
		Ops: []opstream.Op{
			{RequestID: "r1", Method: "GET", URL: "https://api.example.com:443/v1/things", Status: "200"},
		},
		Selected: 0,
		GeneralizeOffer: &GeneralizeOffer{
			Method: "GET",
			URL:    "https://api.example.com:443/v1/things",
			Scheme: "https",
			Host:   "api.example.com",
			Port:   443,
			Path:   "/v1/things",
		},
	}
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"generalize?", "[1]all methods", "[2]all URLs on host", "[3]both", "GET", "https://api.example.com:443/v1/things"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q", want)
		}
	}
}
