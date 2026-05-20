package tui

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/approvals"
)

func sampleSuggestion() *Suggestion {
	return &Suggestion{
		ID:               "sug-1",
		Axis:             "url_segment",
		List:             "allow",
		SourceEntries:    []string{"GET api.example.com/v1/users/123", "GET api.example.com/v1/users/456"},
		SuggestedPattern: "GET api.example.com/v1/users/*",
		Reason:           "consecutive numeric ids",
		AxesRemaining:    1,
	}
}

// TestSuggestionTick_PopulatesAndClears pins #172: a poll result sets
// m.Suggestion; a nil result clears it; a transport error keeps prior
// state (no flicker).
func TestSuggestionTick_PopulatesAndClears(t *testing.T) {
	m := Model{Cols: 100, Rows: 30}
	got, _ := Apply(m, SuggestionTickResult{Suggestion: sampleSuggestion()})
	if got.Suggestion == nil || got.Suggestion.ID != "sug-1" {
		t.Fatalf("tick did not populate m.Suggestion: %+v", got.Suggestion)
	}
	cleared, _ := Apply(got, SuggestionTickResult{Suggestion: nil})
	if cleared.Suggestion != nil {
		t.Errorf("nil tick did not clear m.Suggestion")
	}
	// Transport error keeps prior state.
	kept, _ := Apply(got, SuggestionTickResult{Suggestion: nil, Err: errSample})
	if kept.Suggestion == nil {
		t.Errorf("error tick wrongly cleared m.Suggestion (should keep prior)")
	}
}

var errSample = &stringErr{"boom"}

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }

// TestApplyKeyApprovals_ShiftAcceptDecline pins #172: shift+a / shift+d
// (uppercase A/D runes) on the approvals pane resolve the active
// suggestion; they are inert when no suggestion is offered.
func TestApplyKeyApprovals_ShiftAcceptDecline(t *testing.T) {
	base := Model{Cols: 100, Rows: 30, Focused: PaneApprovals, Suggestion: sampleSuggestion()}

	gotA, cmdA := Apply(base, KeyEvent{Rune: 'A'})
	if acc, ok := cmdA.(CmdSuggestionAccept); !ok || acc.ID != "sug-1" {
		t.Errorf("'A' = %T %+v, want CmdSuggestionAccept{sug-1}", cmdA, cmdA)
	}
	_ = gotA

	_, cmdD := Apply(base, KeyEvent{Rune: 'D'})
	if dec, ok := cmdD.(CmdSuggestionDecline); !ok || dec.ID != "sug-1" {
		t.Errorf("'D' = %T %+v, want CmdSuggestionDecline{sug-1}", cmdD, cmdD)
	}

	// Inert with no suggestion: 'A'/'D' fall through to normal handling
	// (not a suggestion command).
	noSug := Model{Cols: 100, Rows: 30, Focused: PaneApprovals}
	if _, cmd := Apply(noSug, KeyEvent{Rune: 'A'}); cmd != nil {
		if _, ok := cmd.(CmdSuggestionAccept); ok {
			t.Errorf("'A' produced a suggestion accept with no active suggestion")
		}
	}
}

// TestSuggestionActionResult_Status pins the result handling: success
// clears the suggestion and sets LastInfo; failure sets LastErr.
func TestSuggestionActionResult_Status(t *testing.T) {
	m := Model{Cols: 100, Rows: 30, Suggestion: sampleSuggestion()}
	ok, _ := Apply(m, SuggestionActionResult{Action: "accept"})
	if ok.Suggestion != nil {
		t.Errorf("successful accept did not clear m.Suggestion")
	}
	if ok.LastInfo == "" || ok.LastErr != "" {
		t.Errorf("accept status: info=%q err=%q", ok.LastInfo, ok.LastErr)
	}
	bad, _ := Apply(m, SuggestionActionResult{Action: "decline", Err: errSample})
	if bad.LastErr == "" {
		t.Errorf("failed decline did not set LastErr")
	}
}

// TestApplyKeyURLs_SuggestNowKey pins #174: 's' in the URL pane emits
// CmdSuggestNow and sets a scanning hint.
func TestApplyKeyURLs_SuggestNowKey(t *testing.T) {
	m := Model{
		Cols: 100, Rows: 30,
		Focused:         PaneConsole,
		BottomPanel:     BottomPanelURLs,
		BottomPanelOpen: true,
		URLsLocal:       true,
		URLsAnchor:      -1,
	}
	got, cmd := Apply(m, KeyEvent{Rune: 's'})
	if _, ok := cmd.(CmdSuggestNow); !ok {
		t.Fatalf("'s' = %T, want CmdSuggestNow", cmd)
	}
	if got.LastInfo == "" {
		t.Errorf("'s' did not set a scanning hint")
	}
}

// TestSuggestionTick_OnDemandEmptyFeedback pins #174: an on-demand scan
// that finds nothing surfaces a "none found" message rather than
// silently clearing the card.
func TestSuggestionTick_OnDemandEmptyFeedback(t *testing.T) {
	m := Model{Cols: 100, Rows: 30}
	got, _ := Apply(m, SuggestionTickResult{Suggestion: nil, OnDemand: true})
	if got.LastInfo == "" {
		t.Errorf("on-demand empty scan gave no feedback")
	}
	// A periodic (non-on-demand) empty tick stays silent.
	quiet, _ := Apply(m, SuggestionTickResult{Suggestion: nil})
	if quiet.LastInfo != "" {
		t.Errorf("periodic empty tick wrongly set LastInfo=%q", quiet.LastInfo)
	}
}

// TestSuggestionCard_RenderedAndHiddenByHolds pins #172: the suggestion
// renders as a width-fit card in the operations pane when no holds are
// pending, and is hidden when a hold is present (so it never competes
// with approve/deny).
func TestSuggestionCard_RenderedAndHiddenByHolds(t *testing.T) {
	// Width-fit at several widths.
	for _, narrow := range []int{40, 60, 100} {
		for _, l := range formatSuggestionCard(*sampleSuggestion(), narrow-2) {
			if visibleLen(l) > narrow-2 {
				t.Errorf("width %d: suggestion card line exceeds inner: %q", narrow, l)
			}
		}
	}

	var b strings.Builder
	m := Model{Cols: 100, Rows: 14, Focused: PaneApprovals, Suggestion: sampleSuggestion()}
	renderApprovalsPane(&b, m, 14)
	if !strings.Contains(b.String(), "suggestion (url_segment)") {
		t.Errorf("suggestion card not rendered when no holds:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "shift+a") {
		t.Errorf("suggestion card missing accept/decline hint")
	}

	// With a pending hold, the card is hidden.
	var b2 strings.Builder
	mHold := m
	mHold.Holds = []approvals.Snapshot{{ID: "h1"}}
	renderApprovalsPane(&b2, mHold, 14)
	if strings.Contains(b2.String(), "suggestion (url_segment)") {
		t.Errorf("suggestion card shown while a hold is pending:\n%s", b2.String())
	}
}
