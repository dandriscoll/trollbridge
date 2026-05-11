package advisor

import (
	"errors"
	"fmt"
	"strings"
)

// Translator turns trollbridge's native advisor Input into the
// provider-specific wire shape and parses the provider-specific
// response back into the trollbridge Output. Each provider speaks
// its own native API (Anthropic Messages, Azure OpenAI chat
// completions); the Translator is the seam where that shape lives.
//
// HTTPClassifier carries a Translator and owns transport (HTTP
// client, status capture, error wrapping). The Translator owns
// wire shape and headers — including auth, content-type, and any
// provider-required version headers.
type Translator interface {
	// BuildRequest returns the JSON body and the per-request
	// headers (auth + content-type + version) the transport must
	// set on the outgoing POST. The transport supplies nothing
	// further; if a header is required, the translator must emit
	// it. Returning an error here is reserved for misconfiguration
	// (empty api key on a translator that requires one) — input
	// validity is the caller's job.
	BuildRequest(in Input, model, apiKey string) (body []byte, headers map[string]string, err error)

	// ParseResponse decodes the wire body into Output. Errors are
	// wrapped with %w so the caller can distinguish them. Schema
	// errors (200 OK but content didn't carry the requested
	// structured output) wrap ErrAdvisorSchema; transport errors
	// (4xx / 5xx) wrap ErrAdvisorWire.
	ParseResponse(httpStatus int, body []byte) (Output, error)

	// Name returns the operator-facing provider identifier
	// ("anthropic", "aoai"). Used in logs and doctor output.
	Name() string
}

// ErrAdvisorWire wraps any non-2xx upstream response.
var ErrAdvisorWire = errors.New("advisor wire error")

// ErrAdvisorSchema wraps a 2xx upstream response whose body did
// not carry a parseable classifier decision (e.g. the LLM
// returned text instead of invoking the structured-output tool, or
// the tool arguments did not match the expected schema).
var ErrAdvisorSchema = errors.New("advisor schema error")

// TranslatorFor returns the Translator for the configured provider
// name. The endpoint URL is consulted for `aoai` to dispatch
// between the chat-completions translator (URL contains
// `/openai/deployments/<dep>/chat/completions`) and the modern
// Responses API translator (URL contains `/openai/responses`).
// Unknown providers fall back to the anthropic translator with a
// side-channel warning surfaced by the caller.
func TranslatorFor(provider, endpoint string) (Translator, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "anthropic":
		return &anthropicTranslator{}, true
	case "aoai":
		if strings.Contains(endpoint, "/openai/responses") {
			return &aoaiResponsesTranslator{}, true
		}
		return &aoaiTranslator{}, true
	}
	return &anthropicTranslator{}, false
}

// toolName is the structured-output function/tool name both
// translators use. Both providers force the model to invoke this
// tool; the response handler decodes its arguments as the advisor
// Output.
//
// Per docs/alignment-principles.md §4, this name does not identify
// the host application — it names the action ("classify_request")
// generically.
const toolName = "classify_request"

// toolDescription is shown to the model. Per alignment principle §4
// it does not name the host application.
const toolDescription = "Classify the supplied HTTP request against the operator's policy lists and directives. Always invoke this tool exactly once."

// decisionSchema is the JSON Schema for the tool's input. Both
// providers accept this shape (Anthropic input_schema, AOAI
// function.parameters).
func decisionSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"effect": map[string]any{
				"type": "string",
				"enum": []string{
					"allow", "deny", "ask_user",
					"narrow_scope", "redact_and_retry", "prefer_structured_tool",
				},
				"description": "The classifier's decision for this request.",
			},
			"confidence": map[string]any{
				"type":        "string",
				"enum":        []string{"low", "medium", "high"},
				"description": "How certain the classifier is in the chosen effect.",
			},
			"reason": map[string]any{
				"type":        "string",
				"description": "One-sentence justification, suitable for an audit log.",
			},
			"scope": map[string]any{
				"type":        "string",
				"description": "Optional scope hint (e.g. 'host', 'path').",
			},
			"modifiers": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional list of advisory modifiers (e.g. 'redact_authorization_header').",
			},
		},
		"required":             []string{"effect", "confidence", "reason"},
		"additionalProperties": false,
	}
}

// userPrompt builds the human-readable wrapper around the advisor
// Input JSON. Both translators send the same content-shape; the
// directives ride in the system prompt.
//
// Per docs/alignment-principles.md §4, this prompt is generic and
// does not name the host application or describe its role.
func userPrompt(serializedInput []byte) string {
	var b strings.Builder
	b.WriteString("Classify the following HTTP request. Invoke the ")
	b.WriteString(toolName)
	b.WriteString(" tool exactly once.\n\n```json\n")
	b.Write(serializedInput)
	b.WriteString("\n```\n")
	return b.String()
}

// truncateForLog returns at most n bytes of s plus a marker if
// truncated. Used in error wrapping so we surface what came back
// without flooding logs.
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("…(+%d bytes truncated)", len(s)-n)
}
