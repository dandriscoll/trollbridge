package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/opstream"
)

func infoModel(o opstream.Op, focused bool) Model {
	focus := PaneApprovals
	if focused {
		focus = PaneConsole
	}
	return Model{
		Cols: 100, Rows: 30,
		Focused:         focus,
		BottomPanel:     BottomPanelInfo,
		BottomPanelOpen: true,
		Ops:             []opstream.Op{o},
		Selected:        0,
	}
}

// TestRenderInfoPane_SectionLabelsPresent pins the two-section split
// the user asked for (#90): the "request" (group) and "most recent"
// labels both appear.
func TestRenderInfoPane_SectionLabelsPresent(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "200", StartedAt: time.Now(),
		LatencyMS: 42, ResponseSizeBytes: 1024,
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"request", "most recent"} {
		if !strings.Contains(out, want) {
			t.Errorf("section label %q missing", want)
		}
	}
}

// TestRenderInfoPane_ShowsLatencyAndResponseSize pins that the new
// most-recent stats render with their numeric values when set.
func TestRenderInfoPane_ShowsLatencyAndResponseSize(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "200", StartedAt: time.Now(),
		LatencyMS: 142, ResponseSizeBytes: 2318,
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	for _, want := range []string{"142ms", "2318 bytes"} {
		if !strings.Contains(out, want) {
			t.Errorf("info pane render missing %q; first 1200: %q", want, out[:min(1200, len(out))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestRenderInfoPane_InFlightOpShowsPlaceholders pins the "—" fall-
// back for in-flight ops where latency / response size are not yet
// known (#90).
func TestRenderInfoPane_InFlightOpShowsPlaceholders(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "checking", StartedAt: time.Now(),
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "latency    : —") {
		t.Errorf("expected '—' for unknown latency")
	}
	if !strings.Contains(out, "response   : —") {
		t.Errorf("expected '—' for unknown response size")
	}
}

// TestRenderInfoPane_DropsUpdatedField pins the removal: the old
// 'updated' line must no longer appear (#90).
func TestRenderInfoPane_DropsUpdatedField(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "200", StartedAt: time.Now(), UpdatedAt: time.Now(),
		LatencyMS: 42,
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b.String(), "updated    :") {
		t.Errorf("'updated' field should have been removed in #90")
	}
}

// TestRenderInfoPane_HoldIDHiddenWhenEmpty pins that the hold_id
// line only renders when an op has a hold attached.
func TestRenderInfoPane_HoldIDHiddenWhenEmpty(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "200", StartedAt: time.Now(),
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b.String(), "hold_id") {
		t.Errorf("hold_id line should hide when HoldID is empty")
	}
}

// TestRenderInfoPane_HoldIDShownWhenSet — the inverse.
func TestRenderInfoPane_HoldIDShownWhenSet(t *testing.T) {
	o := opstream.Op{
		RequestID: "abc", Method: "GET", URL: "https://api.example.com/v1/x",
		Status: "pending", HoldID: "hold-xyz", StartedAt: time.Now(),
	}
	m := infoModel(o, true)
	var b strings.Builder
	if err := render(&b, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(b.String(), "hold_id    : hold-xyz") {
		t.Errorf("hold_id line missing for pending op")
	}
}
