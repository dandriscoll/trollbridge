package server

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestBuildAdvisorProvider_EmitsModelDefaultWarning closes issue
// #24: when the operator picks the anthropic provider without
// setting llm.model, the translator silently falls back to the
// default model. The startup path must emit a one-time Warn so the
// implicit choice is visible in the operational log.
func TestBuildAdvisorProvider_EmitsModelDefaultWarning(t *testing.T) {
	opLog, buf := captureOpLog(slog.LevelInfo)

	llm := config.LLM{
		Provider: "anthropic",
		Model:    "", // <-- the trigger
		Endpoint: "https://api.anthropic.com/v1/messages",
	}
	_ = buildAdvisorProvider(llm, opLog)

	out := buf.String()
	for _, want := range []string{
		"event=advisor_model_default",
		"provider=anthropic",
		"fallback_model=" + advisor.AnthropicDefaultModel,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in op-log:\n%s", want, out)
		}
	}
}

// TestBuildAdvisorProvider_NoWarningWhenModelExplicit confirms the
// warning is suppressed when llm.model is set, so operators who
// configured the model do not see noise.
func TestBuildAdvisorProvider_NoWarningWhenModelExplicit(t *testing.T) {
	opLog, buf := captureOpLog(slog.LevelInfo)

	llm := config.LLM{
		Provider: "anthropic",
		Model:    "claude-opus-4-7",
		Endpoint: "https://api.anthropic.com/v1/messages",
	}
	_ = buildAdvisorProvider(llm, opLog)

	if strings.Contains(buf.String(), "advisor_model_default") {
		t.Errorf("explicit llm.model should suppress the model_default warning; got:\n%s", buf.String())
	}
}

// TestBuildAdvisorProvider_NoWarningForAOAI confirms the warning
// only fires for the anthropic provider — aoai requires explicit
// endpoint+deployment shape and would fail earlier on empty model
// in a different way.
func TestBuildAdvisorProvider_NoWarningForAOAI(t *testing.T) {
	opLog, buf := captureOpLog(slog.LevelInfo)

	llm := config.LLM{
		Provider: "aoai",
		Model:    "",
		Endpoint: "https://example.openai.azure.com/openai/deployments/x/chat/completions?api-version=2024-02-15-preview",
	}
	_ = buildAdvisorProvider(llm, opLog)

	if strings.Contains(buf.String(), "advisor_model_default") {
		t.Errorf("aoai provider should not trigger the anthropic-specific model_default warning; got:\n%s", buf.String())
	}
}
