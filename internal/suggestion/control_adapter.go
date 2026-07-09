package suggestion

import (
	"context"
	"time"

	"github.com/dandriscoll/trollbridge/internal/control"
)

// ControlAdapter wraps a *Manager so it satisfies
// control.SuggestionProvider. It translates the internal Suggestion
// type into the wire-shape control.SuggestionRow.
type ControlAdapter struct{ M *Manager }

// Active returns the wire-shape row (or nil when there is no
// active suggestion).
func (a ControlAdapter) Active() *control.SuggestionRow {
	if a.M == nil {
		return nil
	}
	s := a.M.Active()
	if s == nil {
		return nil
	}
	row := &control.SuggestionRow{
		SuggestionID:     s.ID,
		Axis:             string(s.Candidate.Axis),
		List:             s.Candidate.List,
		SourceEntries:    s.Candidate.SourceEntries,
		SuggestedPattern: s.Candidate.SuggestedPattern,
		Reason:           s.Reason,
		AxesRemaining:    remainingAxesCount(s.AllAxes, s.OfferedAxes),
		OfferedAt:        s.OfferedAt.UTC().Format(time.RFC3339),
	}
	if pm := s.Candidate.PatternMatch; pm != nil {
		row.PatternName = pm.Pattern
		row.PatternComponents = pm.Components
		row.PatternMethod = pm.Method
	}
	return row
}

// Accept forwards to the manager.
func (a ControlAdapter) Accept(ctx context.Context, id string) error {
	return a.M.Accept(ctx, id)
}

// Decline forwards to the manager.
func (a ControlAdapter) Decline(ctx context.Context, id string) error {
	return a.M.Decline(ctx, id)
}

// Skip forwards the defer-without-decision action to the manager (#214).
func (a ControlAdapter) Skip(ctx context.Context, id string) error {
	return a.M.Skip(ctx, id)
}

// SuggestNow forwards the on-demand scan to the manager (#174).
func (a ControlAdapter) SuggestNow(ctx context.Context) {
	a.M.SuggestNow(ctx)
}
