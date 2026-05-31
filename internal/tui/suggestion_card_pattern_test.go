package tui

import (
	"strings"
	"testing"
)

func samplePatternSuggestion() *Suggestion {
	return &Suggestion{
		ID:               "sug-pat-1",
		Axis:             "pattern:azure_arm",
		List:             "allow",
		SourceEntries:    []string{"e1", "e2", "e3"},
		SuggestedPattern: "azure_arm method=GET subscription=SUB-A",
		Reason:           "fits azure_arm",
		AxesRemaining:    0,
		PatternName:      "azure_arm",
		PatternComponents: map[string]string{
			"subscription":   "SUB-A",
			"resource_group": "rg1",
		},
		PatternMethod: "GET",
	}
}

func TestFormatSuggestionCard_PatternShape(t *testing.T) {
	out := formatSuggestionCard(*samplePatternSuggestion(), 80)
	if len(out) == 0 {
		t.Fatal("expected non-empty card")
	}
	joined := strings.Join(out, "\n")
	// Pattern name visible.
	if !strings.Contains(joined, "pattern:azure_arm") {
		t.Fatalf("card should label pattern:azure_arm; got:\n%s", joined)
	}
	// Fixed components rendered.
	if !strings.Contains(joined, "subscription=SUB-A") {
		t.Fatalf("card should show fixed subscription; got:\n%s", joined)
	}
	if !strings.Contains(joined, "resource_group=rg1") {
		t.Fatalf("card should show fixed resource_group; got:\n%s", joined)
	}
	// Method shown in the rule header.
	if !strings.Contains(joined, "method=GET") {
		t.Fatalf("card should show method=GET; got:\n%s", joined)
	}
	// Effect shown.
	if !strings.Contains(joined, "effect=allow") {
		t.Fatalf("card should show effect=allow; got:\n%s", joined)
	}
	// Source count visible.
	if !strings.Contains(joined, "3 entries") {
		t.Fatalf("card should show source count; got:\n%s", joined)
	}
}

func TestFormatSuggestionCard_FlatShape_Unchanged(t *testing.T) {
	// Regression: flat suggestions render with the legacy
	// "  pattern: ..." line and no pattern-specific structure.
	out := formatSuggestionCard(*sampleSuggestion(), 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "  pattern: GET api.example.com/v1/users/*") {
		t.Fatalf("flat card should keep legacy pattern: line; got:\n%s", joined)
	}
	if strings.Contains(joined, "fixed:") {
		t.Fatalf("flat card should NOT render 'fixed:' line; got:\n%s", joined)
	}
}
