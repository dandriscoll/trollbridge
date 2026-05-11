package advisor

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestComposeSystemPrompt_ReviewBaselineFires pins that review mode
// produces a system prompt that opens with the review baseline.
func TestComposeSystemPrompt_ReviewBaselineFires(t *testing.T) {
	got := composeSystemPrompt(ModeReview, "")
	if !strings.HasPrefix(got, "You are a security policy classifier") {
		t.Errorf("review prompt missing classifier framing; got: %q", got)
	}
	if !strings.Contains(got, "Operating mode: review") {
		t.Errorf("review prompt missing mode line; got: %q", got)
	}
	if strings.Contains(got, "web_search") {
		t.Errorf("review prompt should not mention web_search; got: %q", got)
	}
}

// TestComposeSystemPrompt_NoApplicationDisclosure pins alignment
// principle §4 (docs/alignment-principles.md): the system prompt
// MUST NOT name the host application or describe its role. Catches
// regressions like "You are a security policy advisor for trollbridge,
// an HTTP/HTTPS proxy that gates an AI agent's network egress." that
// shipped in the prior baseline.
func TestComposeSystemPrompt_NoApplicationDisclosure(t *testing.T) {
	for _, mode := range []string{ModeReview, ModeResearch} {
		got := composeSystemPrompt(mode, "")
		// Lowercase compare so regressions in either case fail.
		lower := strings.ToLower(got)
		forbidden := []string{"trollbridge", " proxy ", "proxy.", "gates an ai agent", "ai agent's network", "egress"}
		for _, s := range forbidden {
			if strings.Contains(lower, s) {
				t.Errorf("mode=%s: prompt discloses application detail %q (alignment principle §4); prompt:\n%s", mode, s, got)
			}
		}
	}
}

// TestComposeSystemPrompt_FramesListsAsContext pins alignment
// principles §2 and §3: the lists must be framed as evidence of
// operator intent, not as something the LLM matches against. The
// prompt should also tell the LLM that the engine has confirmed no
// pattern matched (so the LLM doesn't re-match itself).
func TestComposeSystemPrompt_FramesListsAsContext(t *testing.T) {
	for _, mode := range []string{ModeReview, ModeResearch} {
		got := composeSystemPrompt(mode, "")
		// Negative: must not say "authoritative when the request matches their patterns"
		// (the prior wording that invited the LLM to do its own matching).
		if strings.Contains(strings.ToLower(got), "authoritative when") {
			t.Errorf("mode=%s: prompt still uses authority-on-match framing (alignment principle §3); prompt:\n%s", mode, got)
		}
		// Positive: must explicitly tell the LLM the matcher already decided.
		if !strings.Contains(got, "deterministic matcher") {
			t.Errorf("mode=%s: prompt does not name the engine as the matcher (alignment principle §3); prompt:\n%s", mode, got)
		}
		// Positive: must tell the LLM to defer when uncertain (principle §2).
		if !strings.Contains(strings.ToLower(got), "ask_user") {
			t.Errorf("mode=%s: prompt does not name ask_user as the low-confidence fallback (alignment principle §2); prompt:\n%s", mode, got)
		}
	}
}

// TestComposeSystemPrompt_ResearchBaselineFires pins that research
// mode produces a system prompt that names the web_search tool.
func TestComposeSystemPrompt_ResearchBaselineFires(t *testing.T) {
	got := composeSystemPrompt(ModeResearch, "")
	if !strings.Contains(got, "Operating mode: research") {
		t.Errorf("research prompt missing mode line; got: %q", got)
	}
	if !strings.Contains(got, "web_search") {
		t.Errorf("research prompt missing web_search affordance; got: %q", got)
	}
}

// TestComposeSystemPrompt_DirectivesAppendedAfterBaseline pins the
// composition order: trollbridge baseline first, then operator
// directives separated by a blank line.
func TestComposeSystemPrompt_DirectivesAppendedAfterBaseline(t *testing.T) {
	op := "Reject any request that touches /admin paths."
	got := composeSystemPrompt(ModeReview, op)
	idxBase := strings.Index(got, "Operating mode: review")
	idxOp := strings.Index(got, op)
	if idxBase < 0 || idxOp < 0 {
		t.Fatalf("missing one of baseline/operator directive; got: %q", got)
	}
	if idxBase >= idxOp {
		t.Errorf("baseline must appear before operator directive; baseline at %d, operator at %d", idxBase, idxOp)
	}
}

// TestComposeSystemPrompt_EmptyModeDefaultsToReview pins the
// fallback: an empty mode string composes the review baseline.
func TestComposeSystemPrompt_EmptyModeDefaultsToReview(t *testing.T) {
	if got := composeSystemPrompt("", ""); !strings.Contains(got, "Operating mode: review") {
		t.Errorf("empty mode did not default to review; got: %q", got)
	}
}

// TestAnthropicTranslator_ResearchModeIncludesWebSearchTool pins the
// #54 contract: research mode adds the web_search tool to the
// Anthropic request body alongside classify_request.
func TestAnthropicTranslator_ResearchModeIncludesWebSearchTool(t *testing.T) {
	tr := anthropicTranslator{}
	body, _, err := tr.BuildRequest(Input{Host: "x", Path: "/", Mode: ModeResearch}, "claude-x", "k")
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	var seen anthropicRequest
	if err := json.Unmarshal(body, &seen); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var foundDecision, foundSearch bool
	for _, tool := range seen.Tools {
		if tool.Name == toolName {
			foundDecision = true
		}
		if tool.Name == "web_search" && tool.Type == anthropicWebSearchToolType {
			foundSearch = true
			if tool.MaxUses != anthropicWebSearchMaxUses {
				t.Errorf("web_search MaxUses = %d, want %d", tool.MaxUses, anthropicWebSearchMaxUses)
			}
		}
	}
	if !foundDecision {
		t.Errorf("research-mode request missing classify_request tool; tools = %+v", seen.Tools)
	}
	if !foundSearch {
		t.Errorf("research-mode request missing web_search tool; tools = %+v", seen.Tools)
	}
	// tool_choice must still force the structured tool — research is
	// for context, the answer still goes through classify_request.
	if seen.ToolChoice == nil || seen.ToolChoice.Name != toolName {
		t.Errorf("tool_choice did not force classify_request: %+v", seen.ToolChoice)
	}
}

// TestAnthropicTranslator_ReviewModeOmitsWebSearchTool pins the
// inverse: review mode (and empty mode) MUST NOT include web_search.
func TestAnthropicTranslator_ReviewModeOmitsWebSearchTool(t *testing.T) {
	for _, mode := range []string{ModeReview, ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			tr := anthropicTranslator{}
			body, _, err := tr.BuildRequest(Input{Host: "x", Path: "/", Mode: mode}, "claude-x", "k")
			if err != nil {
				t.Fatalf("BuildRequest: %v", err)
			}
			var seen anthropicRequest
			if err := json.Unmarshal(body, &seen); err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, tool := range seen.Tools {
				if tool.Name == "web_search" {
					t.Errorf("mode=%q should not include web_search; tools = %+v", mode, seen.Tools)
				}
			}
			if len(seen.Tools) != 1 {
				t.Errorf("expected exactly 1 tool in review/default mode; got %d", len(seen.Tools))
			}
			// System prompt should still carry the review baseline.
			if !strings.Contains(seen.System, "Operating mode: review") {
				t.Errorf("system prompt missing review baseline; got: %q", seen.System)
			}
		})
	}
}
