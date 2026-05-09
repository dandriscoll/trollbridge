package advisor

import (
	"encoding/json"
	"fmt"
)

// anthropicTranslator speaks the Anthropic Messages API
// (https://docs.anthropic.com/en/api/messages). It forces a single
// tool call to the trollbridge_decision tool so the model's reply
// always carries a structured advisor decision.
//
// Auth: x-api-key (NOT Authorization: Bearer). anthropic-version
// header is required by the API; we pin it to a stable date.
type anthropicTranslator struct{}

// anthropicVersion is the Anthropic API version date pinned in the
// `anthropic-version` header. Bump deliberately; new versions can
// change the response shape.
const anthropicVersion = "2023-06-01"

// anthropicDefaultModel is used when llm.model is empty. Operators
// should set llm.model explicitly; this default is "good enough for
// pre-flight" so doctor doesn't error before the request even leaves.
const anthropicDefaultModel = "claude-3-5-sonnet-latest"

// anthropicMaxTokens caps the assistant response. The advisor only
// needs to emit one tool_use block, so we keep this small.
const anthropicMaxTokens = 1024

func (anthropicTranslator) Name() string { return "anthropic" }

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model      string                 `json:"model"`
	MaxTokens  int                    `json:"max_tokens"`
	System     string                 `json:"system,omitempty"`
	Messages   []anthropicMessage     `json:"messages"`
	Tools      []anthropicTool        `json:"tools,omitempty"`
	ToolChoice *anthropicToolChoice   `json:"tool_choice,omitempty"`
}

func (anthropicTranslator) BuildRequest(in Input, model, apiKey string) ([]byte, map[string]string, error) {
	if model == "" {
		model = anthropicDefaultModel
	}
	serialized, err := json.Marshal(in)
	if err != nil {
		return nil, nil, fmt.Errorf("anthropic: marshal input: %w", err)
	}
	req := anthropicRequest{
		Model:     model,
		MaxTokens: anthropicMaxTokens,
		System:    in.Directives,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt(serialized)},
		},
		Tools: []anthropicTool{{
			Name:        toolName,
			Description: toolDescription,
			InputSchema: decisionSchema(),
		}},
		ToolChoice: &anthropicToolChoice{Type: "tool", Name: toolName},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}
	hdr := map[string]string{
		"Content-Type":      "application/json",
		"anthropic-version": anthropicVersion,
	}
	if apiKey != "" {
		hdr["x-api-key"] = apiKey
	}
	return body, hdr, nil
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicResponse struct {
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Content    []anthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (anthropicTranslator) ParseResponse(httpStatus int, body []byte) (Output, error) {
	if httpStatus < 200 || httpStatus >= 300 {
		return Output{}, fmt.Errorf("%w: anthropic http %d: %s",
			ErrAdvisorWire, httpStatus, truncateForLog(string(body), 256))
	}
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Output{}, fmt.Errorf("%w: anthropic decode: %v: %s",
			ErrAdvisorSchema, err, truncateForLog(string(body), 256))
	}
	if resp.Error != nil {
		return Output{}, fmt.Errorf("%w: anthropic api error: %s: %s",
			ErrAdvisorSchema, resp.Error.Type, resp.Error.Message)
	}
	for _, block := range resp.Content {
		if block.Type != "tool_use" || block.Name != toolName {
			continue
		}
		var out Output
		if err := json.Unmarshal(block.Input, &out); err != nil {
			return Output{}, fmt.Errorf("%w: anthropic tool_use input decode: %v: %s",
				ErrAdvisorSchema, err, truncateForLog(string(block.Input), 256))
		}
		return out, nil
	}
	return Output{}, fmt.Errorf("%w: anthropic response had no tool_use block for %q (stop_reason=%q); model returned text instead of invoking the structured-output tool",
		ErrAdvisorSchema, toolName, resp.StopReason)
}
